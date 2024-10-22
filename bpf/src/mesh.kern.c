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
        FSM_DBG("[DBG] tc_ingress ========\n");
        FSM_DBG("[DBG] tc_ingress pkt->l34m saddr4  %pI4 source  %d\n",
                &pkt->l34.saddr4, ntohs(pkt->l34.source));
        FSM_DBG("[DBG] tc_ingress pkt->l34m daddr4  %pI4 dest    %d\n",
                &pkt->l34.daddr4, ntohs(pkt->l34.dest));
    }

    // return dp_ing_fc_main(skb, pkt);
    return TC_ACT_OK;
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
        FSM_DBG("[DBG] tc_egress ========\n");
        FSM_DBG("[DBG] tc_egress pkt->l34m saddr4  %pI4 source  %d\n",
                &pkt->l34.saddr4, ntohs(pkt->l34.source));
        FSM_DBG("[DBG] tc_egress pkt->l34m daddr4  %pI4 dest    %d\n",
                &pkt->l34.daddr4, ntohs(pkt->l34.dest));
    }
    // return dp_ing_fc_main(skb, pkt);
    return TC_ACT_OK;
}

SEC("classifier/handshake")
int tc_hand_shake_func(skb_t *skb)
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
int tc_conn_track_func(skb_t *skb)
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
int tc_pass(skb_t *skb)
{
    return TC_ACT_OK;
}

SEC("classifier/drop")
int tc_drop(skb_t *skb)
{
    return TC_ACT_SHOT;
}