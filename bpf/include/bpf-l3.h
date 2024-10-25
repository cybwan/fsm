#ifndef __F4_BPF_L3_H__
#define __F4_BPF_L3_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"
#include "bpf-ct.h"
#include "bpf-lb.h"

INTERNAL(int)
dp_do_ctops(skb_t *skb, xpkt_t *pkt, fib4_ops_t *fa, ct_op_t *act)
{
    if (!act) {
        goto conn_track;
    }

    pkt->ctx.phit |= F4_DP_CTM_HIT;

    act->lts = bpf_ktime_get_ns();

    if (act->nf == NF_DO_CTTK) {
        goto conn_track;
    } else if (act->nf == NF_DO_NOOP) {
        nf_rdr_t *ar = &act->nfs.rdr;
        if (pkt->ctx.l4fin) {
            ar->fin = 1;
        }

        if (ar->fin == 1) {
            goto conn_track;
        }
    } else if (act->nf == NF_DO_RDRT) {
        nf_rdr_t *ar = &act->nfs.rdr;
        if (pkt->ctx.l4fin) {
            ar->fin = 1;
        }

        if (ar->fin == 1) {
            goto conn_track;
        }

        F4_PPLN_RDR_PRIO(pkt);
        pkt->ctx.oport = ar->oport;
    } else if (act->nf == NF_DO_SNAT || act->nf == NF_DO_DNAT) {
        nf_nat_t *na;
        fib4_op_t *ta =
            &fa->ops[act->nf == NF_DO_SNAT ? NF_DO_SNAT : NF_DO_DNAT];
        ta->nf = act->nf;
        memcpy(&ta->nfs.nat, &act->nfs.nat, sizeof(act->nfs.nat));

        na = &act->nfs.nat;

        if (pkt->ctx.l4fin) {
            na->fin = 1;
        }

        xpkt_nat_load(skb, pkt, na, act->nf == NF_DO_SNAT ? 1 : 0);

        if (na->fin == 1 || na->doct || pkt->ctx.goct) {
            goto conn_track;
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

conn_track:
    return xpkt_tail_call(skb, pkt, fa, FSM_CNI_CONNTRACK_PROG_ID);
}

INTERNAL(int)
dp_do_ing_ct(skb_t *skb, xpkt_t *pkt, fib4_ops_t *fa)
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
    return dp_do_ctops(skb, pkt, fa, act);
}

#endif