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

#include "bpf-utils.h"
#include "bpf-config.h"
#include "bpf-dp.h"
#include "bpf-mdi.h"
#include "bpf-mdefs.h"
#include "bpf-cdefs.h"
#include "bpf-if.h"
#include "bpf-l2.h"
#include "bpf-l3.h"
#include "bpf-fib.h"
#include "bpf-lb.h"
#include "bpf-ct.h"
#include "bpf-pkt.h"

char __LICENSE[] SEC("license") = "GPL";

SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *ctx)
{
    int z = 0;
    struct xpkt *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }
    memset(pkt, 0, sizeof *pkt);

    pkt->pm.igr = 1;
    pkt->pm.ifi = ctx->ingress_ifindex;

    xpkt_decode(ctx, pkt, 1);

    FSM_DBG("[DBG] tc_ingress ========\n");
    FSM_DBG("[DBG] tc_ingress pkt->l34m saddr4  %pI4 source  %d\n",
            &pkt->l34.saddr4, ntohs(pkt->l34.source));
    FSM_DBG("[DBG] tc_ingress pkt->l34m daddr4  %pI4 dest    %d\n",
            &pkt->l34.daddr4, ntohs(pkt->l34.dest));

    // return dp_ing_fc_main(ctx, pkt);
    return TC_ACT_OK;
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *ctx)
{
    int z = 0;
    struct xpkt *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }
    memset(pkt, 0, sizeof *pkt);

    pkt->pm.egr = 1;
    pkt->pm.ifi = ctx->ingress_ifindex;

    xpkt_decode(ctx, pkt, 1);

    FSM_DBG("[DBG] tc_egress ========\n");
    FSM_DBG("[DBG] tc_egress pkt->l34m saddr4  %pI4 source  %d\n",
            &pkt->l34.saddr4, ntohs(pkt->l34.source));
    FSM_DBG("[DBG] tc_egress pkt->l34m daddr4  %pI4 dest    %d\n",
            &pkt->l34.daddr4, ntohs(pkt->l34.dest));

    // return dp_ing_fc_main(ctx, pkt);
    return TC_ACT_OK;
}

SEC("classifier/handshake")
int tc_hand_shake_func(struct __sk_buff *ctx)
{
    int z = 0;
    struct xpkt *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    pkt->pm.phit |= F4_DP_FC_HIT;
    pkt->pm.tc = 1;

    if (pkt->pm.pipe_act & F4_PIPE_PASS || pkt->pm.pipe_act & F4_PIPE_TRAP) {
        pkt->pm.rcode |= F4_PIPE_RC_MPT_PASS;
        return TC_ACT_OK;
    }

    return dp_ing_sh_main(ctx, pkt);
}

SEC("classifier/conntrack")
int tc_conn_track_func(struct __sk_buff *ctx)
{
    int z = 0;
    struct xpkt *pkt;

    pkt = bpf_map_lookup_elem(&fsm_xpkts, &z);
    if (!pkt) {
        return TC_ACT_SHOT;
    }

    return dp_ing_ct_main(ctx, pkt);
}

SEC("classifier/pass")
int tc_pass(struct __sk_buff *ctx) { return TC_ACT_OK; }

SEC("classifier/drop")
int tc_drop(struct __sk_buff *ctx) { return TC_ACT_SHOT; }