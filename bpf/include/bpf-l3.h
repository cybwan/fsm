#ifndef __F4_BPF_L3_H__
#define __F4_BPF_L3_H__

#include "bpf-dbg.h"
#include "bpf-ct.h"
#include "bpf-lb.h"

__attribute__((__always_inline__)) static inline int
dp_do_ctops(void *ctx, struct xpkt *pkt, void *fa_, struct dp_ct_tact *act)
{
    struct xpkt_fib4_ops *fa = fa_;
    if (!act) {
        goto ct_trk;
    }

    pkt->pm.phit |= F4_DP_CTM_HIT;

    act->lts = bpf_ktime_get_ns();

    fa->ca.cidx = act->ca.cidx;
    fa->ca.fwrid = act->ca.fwrid;

    if (act->ca.act_type == DP_SET_DO_CT) {
        goto ct_trk;
    } else if (act->ca.act_type == DP_SET_NOP) {
        struct dp_rdr_act *ar = &act->port_act;
        if (pkt->pm.l4fin) {
            ar->fr = 1;
        }

        if (ar->fr == 1) {
            goto ct_trk;
        }

    } else if (act->ca.act_type == DP_SET_RDR_PORT) {
        struct dp_rdr_act *ar = &act->port_act;
        if (pkt->pm.l4fin) {
            ar->fr = 1;
        }

        if (ar->fr == 1) {
            goto ct_trk;
        }

        F4_PPLN_RDR_PRIO(pkt);
        pkt->pm.oport = ar->oport;
    } else if (act->ca.act_type == DP_SET_SNAT ||
               act->ca.act_type == DP_SET_DNAT) {
        struct dp_nat_act *na;
        struct xpkt_fib4_op *ta =
            &fa->ops[act->ca.act_type == DP_SET_SNAT ? DP_SET_SNAT
                                                     : DP_SET_DNAT];
        ta->ca.act_type = act->ca.act_type;
        memcpy(&ta->nat_act, &act->nat_act, sizeof(act->nat_act));

        na = &act->nat_act;

        if (pkt->pm.l4fin) {
            na->fr = 1;
        }

        xpkt_nat_set(ctx, pkt, na, act->ca.act_type == DP_SET_SNAT ? 1 : 0);

        if (na->fr == 1 || na->doct || pkt->pm.goct) {
            goto ct_trk;
        }

        F4_PPLN_RDR(pkt);
    } else if (act->ca.act_type == DP_SET_TOCP) {
        F4_PPLN_PASSC(pkt, F4_PIPE_RC_ACL_TRAP);
    } else {
        /* Same for DP_SET_DROP */
        F4_PPLN_DROPC(pkt, F4_PIPE_RC_ACT_DROP);
    }

    if (pkt->l34.proto == IPPROTO_TCP) {
        dp_run_ctact_helper(pkt, act);
    }

    return 0;

ct_trk:
    return xpkt_tail_call(ctx, pkt, fa_, FSM_CNI_CONNTRACK_PROG_ID);
}

__attribute__((__always_inline__)) static inline int
dp_do_ing_ct(void *ctx, struct xpkt *pkt, void *fa_)
{

    struct dp_ct_key key;
    struct dp_ct_tact *act;

    CT_KEY_GEN(&key, pkt);

    // pkt->pm.table_id = F4_DP_CT_MAP;
    act = bpf_map_lookup_elem(&f4gw_ct, &key);
    return dp_do_ctops(ctx, pkt, fa_, act);
}

__attribute__((__always_inline__)) static inline int
dp_l3_fwd(void *ctx, struct xpkt *pkt, void *fa)
{
    if (pkt->l2.dl_type == htons(ETH_P_IP)) {
        if (pkt->pm.nf && pkt->nat.nv6 != 0) {
            pkt->nat.xlate_proto = 1;
            // dp_do_ipv6_fwd(ctx, pkt, fa);
        } else {
            // dp_do_ipv4_fwd(ctx, pkt, fa);
        }
    } else if (pkt->l2.dl_type == htons(ETH_P_IPV6)) {
        if (pkt->pm.nf && pkt->nat.nv6 == 0) {
            pkt->nat.xlate_proto = 1;
            // dp_do_ipv4_fwd(ctx, pkt, fa);
        } else {
            // dp_do_ipv6_fwd(ctx, pkt, fa);
        }
    }
    return 0;
}

__attribute__((__always_inline__)) static inline int
dp_ing_l3(void *ctx, struct xpkt *pkt, void *fa)
{
    dp_do_ing_ct(ctx, pkt, fa);
    // dp_l3_fwd(ctx, pkt, fa);
    return 0;
}

#endif