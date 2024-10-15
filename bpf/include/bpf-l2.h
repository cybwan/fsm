#ifndef __F4_BPF_L2_H__ 
#define __F4_BPF_L2_H__

#include "bpf-dbg.h"
#include "bpf-l3.h"

static int __always_inline
dp_eg_l2(void *ctx,  struct xpkt *pkt, void *fa)
{
  // /* Any processing based on results from L3 */
  // if (pkt->pm.pipe_act & F4_PIPE_RDR_MASK) {
  //   return 0;
  // }   
      
  // if (pkt->pm.nh_num != 0) {
  //   dp_do_nh_lkup(ctx, xf, fa);
  // }

  // dp_do_map_stats(ctx, xf, F4_DP_TX_BD_STATS_MAP, pkt->pm.bd);

  // dp_do_dmac_lkup(ctx, xf, fa);
  return 0;
}

static int __always_inline
dp_ing_fwd(void *ctx,  struct xpkt *pkt, void *fa)
{
  dp_ing_l3(ctx, pkt, fa);
  return dp_eg_l2(ctx, pkt, fa);
}

static int __always_inline
dp_ing_l2_top(void *ctx,  struct xpkt *pkt, void *fa)
{
  // dp_do_smac_lkup(ctx, pkt, fa);
  // dp_do_tmac_lkup(ctx, pkt, fa);
  // dp_do_tun_lkup(ctx, pkt, fa);
  return 0;
}

static int __always_inline
dp_ing_l2(void *ctx,  struct xpkt *pkt, void *fa)
{
  // dp_ing_l2_top(ctx, pkt, fa);
  return dp_ing_fwd(ctx, pkt, fa);
}

#endif