#ifndef __F4_BPF_L2_H__
#define __F4_BPF_L2_H__

#include "bpf-dbg.h"
#include "bpf-l3.h"

__attribute__((__always_inline__)) static inline int
dp_eg_l2(skb_t *skb, struct xpkt *pkt, void *fa)
{
    // /* Any processing based on results from L3 */
    // if (pkt->ctx.act & F4_PIPE_RDR_MASK) {
    //   return 0;
    // }

    // if (pkt->ctx.nh_num != 0) {
    //   dp_do_nh_lkup(skb, xf, fa);
    // }

    // dp_do_map_stats(skb, xf, F4_DP_TX_BD_STATS_MAP, pkt->ctx.bd);

    // dp_do_dmac_lkup(skb, xf, fa);
    return 0;
}

__attribute__((__always_inline__)) static inline int
dp_ing_fwd(skb_t *skb, struct xpkt *pkt, void *fa)
{
    dp_ing_l3(skb, pkt, fa);
    return dp_eg_l2(skb, pkt, fa);
}

__attribute__((__always_inline__)) static inline int
dp_ing_l2_top(skb_t *skb, struct xpkt *pkt, void *fa)
{
    // dp_do_smac_lkup(skb, pkt, fa);
    // dp_do_tmac_lkup(skb, pkt, fa);
    // dp_do_tun_lkup(skb, pkt, fa);
    return 0;
}

__attribute__((__always_inline__)) static inline int
dp_ing_l2(skb_t *skb, struct xpkt *pkt, void *fa)
{
    // dp_ing_l2_top(skb, pkt, fa);
    return dp_ing_fwd(skb, pkt, fa);
}

#endif