#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf-macros.h"
#include "bpf-utils.h"
#include "bpf-config.h"
#include "bpf-dp.h"
#include "bpf-mdi.h"
#include "bpf-mdefs.h"
#include "bpf-cdefs.h"
#include "bpf-if.h"
#include "bpf-l3.h"
#include "bpf-fib.h"
#include "bpf-lb.h"
#include "bpf-ct.h"
#include "bpf-pkt.h"

char __LICENSE[] SEC("license") = "GPL";

SEC("classifier/sidecar/ingress")
int sidecar_ingress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }
    memset(pkt, 0, sizeof *pkt);

    pkt->ctx.igr = 1;
    pkt->ctx.ifi = skb->ingress_ifindex;

    xpkt_decode(skb, pkt, 1);

    if (F4_DEBUG_IGR(pkt)) {
        FSM_DBG("[DBG] tc_igr ========\n");
        // FSM_DBG("[DBG] tc_igr pkt->l34 saddr4 %pI4 sport %d\n",
        //         &pkt->l34.saddr4, ntohs(pkt->l34.sport));
        // FSM_DBG("[DBG] tc_igr pkt->l34 daddr4 %pI4 dport %d\n",
        //         &pkt->l34.daddr4, ntohs(pkt->l34.dport));
        void *dend = XPKT_PTR(XPKT_DATA_END(skb));
        struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
        if ((void *)(t + 1) > dend) {
            return -1;
        }
        FSM_DBG("[DBG] tc_igr syn: %d ack: %d fin: %d\n", t->syn, t->ack,
                t->fin);
        FSM_DBG("[DBG] tc_igr seq: %u ack_seq: %u\n", ntohl(t->seq),
                ntohl(t->ack_seq));
        FSM_DBG("[DBG] tc_igr ingress_ifindex: %u ifindex: %u\n",
                skb->ingress_ifindex, skb->ifindex);
    }

    return dp_ing_fc_main(skb, pkt);
    // return TC_ACT_OK;
}

SEC("classifier/sidecar/egress")
int sidecar_egress(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }
    memset(pkt, 0, sizeof *pkt);

    pkt->ctx.egr = 1;
    pkt->ctx.ifi = skb->ingress_ifindex;

    xpkt_decode(skb, pkt, 1);

    if (F4_DEBUG_EGR(pkt)) {
        FSM_DBG("[DBG] tc_egr ========\n");
        // FSM_DBG("[DBG] tc_egr pkt->l34 saddr4 %pI4 sport %d\n",
        //         &pkt->l34.saddr4, ntohs(pkt->l34.sport));
        // FSM_DBG("[DBG] tc_egr pkt->l34 daddr4 %pI4 dport %d\n",
        //         &pkt->l34.daddr4, ntohs(pkt->l34.dport));
        void *dend = XPKT_PTR(XPKT_DATA_END(skb));
        struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
        if ((void *)(t + 1) > dend) {
            return -1;
        }
        FSM_DBG("[DBG] tc_egr syn: %d ack: %d fin: %d\n", t->syn, t->ack,
                t->fin);
        FSM_DBG("[DBG] tc_egr seq: %u ack_seq: %u\n", ntohl(t->seq),
                ntohl(t->ack_seq));
        FSM_DBG("[DBG] tc_egr ingress_ifindex: %u ifindex: %u\n",
                skb->ingress_ifindex, skb->ifindex);
    }
    return dp_ing_fc_main(skb, pkt);
    // return TC_ACT_OK;
}

SEC("classifier/handshake")
int sidecar_hand_shake(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    pkt->ctx.phit |= F4_DP_FC_HIT;
    pkt->ctx.tc = 1;

    if (pkt->ctx.act & F4_PIPE_PASS || pkt->ctx.act & F4_PIPE_TRAP) {
        pkt->ctx.rcode |= F4_PIPE_RC_MPT_PASS;
        return TC_ACT_OK;
    }

    return xpkt_handshake_proc(skb, pkt);
}

SEC("classifier/conntrack")
int sidecar_conn_track(skb_t *skb)
{
    int z = 0;
    xpkt_t *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    return xpkt_conntrack_proc(skb, pkt);
}

SEC("classifier/pass")
int sidecar_pass(skb_t *skb)
{
    return TC_ACT_OK;
}

SEC("classifier/drop")
int sidecar_drop(skb_t *skb)
{
    return TC_ACT_SHOT;
}