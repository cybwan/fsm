#ifndef __F4_BPF_L3_H__
#define __F4_BPF_L3_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"
#include "bpf-ct.h"
#include "bpf-lb.h"

INTERNAL(int)
dp_do_ctops(skb_t *skb, xpkt_t *pkt, void *fa_, ct_op_t *act)
{
    struct xpkt_fib4_ops *fa = fa_;
    if (!act) {
        goto ct_trk;
    }

    pkt->ctx.phit |= F4_DP_CTM_HIT;

    act->lts = bpf_ktime_get_ns();

    if (act->act_type == NF_DO_CT) {
        goto ct_trk;
    } else if (act->act_type == NF_DO_NOP) {
        struct dp_rdr_act *ar = &act->port_act;
        if (pkt->ctx.l4fin) {
            ar->fr = 1;
        }

        if (ar->fr == 1) {
            goto ct_trk;
        }

    } else if (act->act_type == NF_DO_RDR) {
        struct dp_rdr_act *ar = &act->port_act;
        if (pkt->ctx.l4fin) {
            ar->fr = 1;
        }

        if (ar->fr == 1) {
            goto ct_trk;
        }

        F4_PPLN_RDR_PRIO(pkt);
        pkt->ctx.oport = ar->oport;
    } else if (act->act_type == NF_DO_SNAT || act->act_type == NF_DO_DNAT) {
        struct dp_nat_act *na;
        struct xpkt_fib4_op *ta =
            &fa->ops[act->act_type == NF_DO_SNAT ? NF_DO_SNAT : NF_DO_DNAT];
        ta->act_type = act->act_type;
        memcpy(&ta->nat_act, &act->nat_act, sizeof(act->nat_act));

        na = &act->nat_act;

        if (pkt->ctx.l4fin) {
            na->fr = 1;
        }

        xpkt_nat_load(skb, pkt, na, act->act_type == NF_DO_SNAT ? 1 : 0);

        if (na->fr == 1 || na->doct || pkt->ctx.goct) {
            goto ct_trk;
        }

        F4_PPLN_RDR(pkt);
    } else {
        /* Same for NF_DO_DROP */
        F4_PPLN_DROPC(pkt, F4_PIPE_RC_ACT_DROP);
    }

    if (pkt->l34.proto == IPPROTO_TCP) {
        dp_run_ctact_helper(pkt, act);
    }

    return 0;

ct_trk:
    return xpkt_tail_call(skb, pkt, fa_, FSM_CNI_CONNTRACK_PROG_ID);
}

INTERNAL(int)
dp_do_ing_ct(skb_t *skb, xpkt_t *pkt, void *fa_)
{

    ct_key_t key;
    ct_op_t *act;

    XADDR_COPY(key.daddr, pkt->l34.daddr);
    XADDR_COPY(key.saddr, pkt->l34.saddr);
    key.sport = pkt->l34.sport;
    key.dport = pkt->l34.dport;
    key.proto = pkt->l34.proto;
    key.v6 = pkt->l2.dl_type == ntohs(ETH_P_IPV6) ? 1 : 0;

    act = bpf_map_lookup_elem(&fsm_ct, &key);
    return dp_do_ctops(skb, pkt, fa_, act);
}

INTERNAL(int)
dp_ing_l3(skb_t *skb, xpkt_t *pkt, void *fa)
{
    dp_do_ing_ct(skb, pkt, fa);
    return 0;
}

#endif