#ifndef __F4_BPF_DEVIF_H__ 
#define __F4_BPF_DEVIF_H__

#include "bpf-dbg.h"
#include "bpf-pkt.h"
#include "bpf-l2.h"
#include "bpf-lb.h"

static int __always_inline
dp_redir_packet(void *ctx,  struct xpkt *pkt)
{
  return TC_ACT_REDIRECT;
}

static int __always_inline
dp_insert_fcv4(void *ctx, struct xpkt *pkt, struct dp_fc_tacts *acts)
{
  struct dp_fcv4_key *key;
  int z = 0;

  int oif = pkt->nat.nxifi;
  if (oif) {
    acts->ca.oaux = oif;
  } 

  key = bpf_map_lookup_elem(&f4gw_xfck, &z);
  if (key == NULL) {
    return -1;
  }

  if (bpf_map_lookup_elem(&f4gw_fc_v4, key) != NULL) {
    return 1;
  }
  
  acts->pten = pkt->pm.pten;
  bpf_map_update_elem(&f4gw_fc_v4, key, acts, BPF_ANY);
  return 0;
}

static int __always_inline
dp_pipe_check_res(void *ctx, struct xpkt *pkt, void *fa)
{
  if (pkt->pm.pipe_act) {

    if (pkt->pm.pipe_act & F4_PIPE_DROP) {
      return TC_ACT_SHOT;
    }

    if (pkt->pm.pipe_act & F4_PIPE_RDR) {
      // DP_XMAC_CP(pkt->l2m.dl_src, pkt->nm.nxmac);
      // DP_XMAC_CP(pkt->l2m.dl_dst, pkt->nm.nrmac);
      pkt->pm.oport = pkt->nat.nxifi;
    }

    if (dp_unparse_packet_always(ctx, pkt) != 0) {
        return TC_ACT_SHOT;
    }

    if (pkt->pm.pipe_act & F4_PIPE_RDR_MASK) {
      // if (dp_unparse_packet(ctx, pkt) != 0) {
      //   return TC_ACT_SHOT;
      // }
      // if (pkt->pm.f4) {
      //   if (dp_f4_packet(ctx, pkt) != 0) {
      //     return TC_ACT_SHOT;
      //   }
      // }
      // return bpf_redirect(pkt->pm.oport, BPF_F_INGRESS);
    }

  }
  return TC_ACT_OK; /* FIXME */
}

static int __always_inline 
dp_ing_ct_main(void *ctx,  struct xpkt *pkt)
{
  int val = 0;
  struct dp_fc_tacts *fa = NULL;

  fa = bpf_map_lookup_elem(&f4gw_fcas, &val);
  if (!fa) return TC_ACT_SHOT;

  if (pkt->pm.igr && (pkt->pm.phit & F4_DP_CTM_HIT) == 0) {
    dp_do_nat(ctx, pkt);
  }

  val = dp_ct_in(ctx, pkt);
  if (val < 0) {
    return TC_ACT_OK;
  }

  dp_l3_fwd(ctx, pkt, fa);
  dp_eg_l2(ctx, pkt, fa);

res_end:
  if (1) {
    int ret = dp_pipe_check_res(ctx, pkt, fa);
    return ret;
  }
}

static int __always_inline
dp_ing_sh_main(void *ctx,  struct xpkt *pkt)
{
  struct dp_fc_tacts *fa = NULL;
  int z = 0;

  fa = bpf_map_lookup_elem(&f4gw_fcas, &z);
  if (!fa) return 0;

  /* No nonsense no loop */
  fa->ca.ftrap = 0;
  fa->ca.cidx = 0;
  fa->zone = 0;
  fa->its = bpf_ktime_get_ns();
#pragma clang loop unroll(full)
  for (z = 0; z < F4_FCV4_MAP_ACTS; z++) {
    fa->fcta[z].ca.act_type = 0;
  }

  // F4_DBG_PRINTK("[INGR] START--\n");

  // /* If there are any packets marked for mirroring, we do
  //  * it here and immediately get it out of way without
  //  * doing any further processing
  //  */
  // if (pkt->pm.mirr != 0) {
  //   dp_do_mirr_lkup(ctx, pkt);
  //   goto out;
  // }

  // dp_ing(ctx, pkt);

  /* If there are pipeline errors at this stage,
   * we again skip any further processing
   */
  if (pkt->pm.pipe_act || pkt->pm.tc == 0) {
    goto out;
  }

  dp_ing_l2(ctx, pkt, fa);

  /* fast-cache is used only when certain conditions are met */
  if (F4_PIPE_FC_CAP(pkt)) {
    fa->zone = pkt->pm.zone;
    dp_insert_fcv4(ctx, pkt, fa);
  }

out:
  bpf_tail_call(ctx, &fsm_progs, F4_DP_CT_PGM_ID);
  return TC_ACT_OK;
}

#endif