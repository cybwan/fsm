#ifndef __F4_BPF_DEVIF_H__
#define __F4_BPF_DEVIF_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"
#include "bpf-pkt.h"
#include "bpf-l3.h"
#include "bpf-lb.h"

INTERNAL(int)
xpkt_fib4_insert(skb_t *skb, xpkt_t *pkt, struct xpkt_fib4_ops *ops)
{
    struct xpkt_fib4_key *key;
    int z = 0;

    key = bpf_map_lookup_elem(&fsm_fib4_key, &z);
    if (key == NULL) {
        return -1;
    }

    if (bpf_map_lookup_elem(&fsm_fib4, key) != NULL) {
        return 1;
    }

    bpf_map_update_elem(&fsm_fib4, key, ops, BPF_ANY);
    return 0;
}

INTERNAL(int)
dp_pipe_check_res(skb_t *skb, xpkt_t *pkt, void *fa)
{
    if (pkt->ctx.act) {

        if (pkt->ctx.act & F4_PIPE_DROP) {
            return TC_ACT_SHOT;
        }

        if (pkt->ctx.act & F4_PIPE_RDR) {
            // XMAC_COPY(pkt->l2m.dl_src, pkt->nm.nxmac);
            // XMAC_COPY(pkt->l2m.dl_dst, pkt->nm.nrmac);
            pkt->ctx.oport = pkt->nat.nxifi;
        }

        if (xpkt_encode_packet_always(skb, pkt) != 0) {
            return TC_ACT_SHOT;
        }

        if (pkt->ctx.act & F4_PIPE_RDR_MASK) {
            // if (xpkt_encode_packet(skb, pkt) != 0) {
            //   return TC_ACT_SHOT;
            // }
            // if (pkt->ctx.f4) {
            //   if (dp_f4_packet(skb, pkt) != 0) {
            //     return TC_ACT_SHOT;
            //   }
            // }
            // return bpf_redirect(pkt->ctx.oport, BPF_F_INGRESS);
        }
    }
    return TC_ACT_OK; /* FIXME */
}

INTERNAL(int)
xpkt_conntrack_proc(skb_t *skb, xpkt_t *pkt)
{
    int val = 0;
    struct xpkt_fib4_ops *fa = NULL;

    fa = bpf_map_lookup_elem(&fsm_fib4_ops, &val);
    if (!fa)
        return TC_ACT_SHOT;

    if (pkt->ctx.igr && (pkt->ctx.phit & F4_DP_CTM_HIT) == 0) {
        xpkt_nat_proc(skb, pkt);
    }

    val = dp_ct_in(skb, pkt);
    if (val < 0) {
        return TC_ACT_OK;
    }

res_end:
    return dp_pipe_check_res(skb, pkt, fa);
}

INTERNAL(int)
xpkt_handshake_proc(skb_t *skb, xpkt_t *pkt)
{
    struct xpkt_fib4_ops *fa = NULL;
    int z = 0;

    fa = bpf_map_lookup_elem(&fsm_fib4_ops, &z);
    if (!fa)
        return 0;

    /* No nonsense no loop */
    fa->its = bpf_ktime_get_ns();
#pragma clang loop unroll(full)
    for (z = 0; z < F4_FCV4_MAP_ACTS; z++) {
        fa->ops[z].act_type = 0;
    }

    /* If there are pipeline errors at this stage,
     * we again skip any further processing
     */
    if (pkt->ctx.act || pkt->ctx.tc == 0) {
        goto out;
    }

    dp_do_ing_ct(skb, pkt, fa);

    /* fast-cache is used only when certain conditions are met */
    if (F4_PIPE_FC_CAP(pkt)) {
        xpkt_fib4_insert(skb, pkt, fa);
    }

out:
    bpf_tail_call(skb, &fsm_progs, FSM_CNI_CONNTRACK_PROG_ID);
    return TC_ACT_OK;
}

#endif