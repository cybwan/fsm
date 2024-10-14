#ifndef __F4_BPF_DEVIF_H__ 
#define __F4_BPF_DEVIF_H__

#include "bpf-dbg.h"
#include "bpf-pkt.h"
#include "bpf-l2.h"
#include "bpf-lb.h"

static int __always_inline
dp_redir_packet(void *ctx,  struct xfrm *xf)
{
  return DP_REDIRECT;
}

static int __always_inline
dp_insert_fcv4(void *ctx, struct xfrm *xf, struct dp_fc_tacts *acts)
{
  struct dp_fcv4_key *key;
  int z = 0;

  int oif = xf->nm.nxifi;
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
  
  acts->pten = xf->pm.pten;
  bpf_map_update_elem(&f4gw_fc_v4, key, acts, BPF_ANY);
  return 0;
}

static int __always_inline
dp_pipe_check_res(void *ctx, struct xfrm *xf, void *fa)
{
  if (xf->pm.pipe_act) {

    if (xf->pm.pipe_act & F4_PIPE_DROP) {
      return DP_DROP;
    }

    if (xf->pm.pipe_act & F4_PIPE_RDR) {
      // DP_XMAC_CP(xf->l2m.dl_src, xf->nm.nxmac);
      // DP_XMAC_CP(xf->l2m.dl_dst, xf->nm.nrmac);
      xf->pm.oport = xf->nm.nxifi;
    }

    if (dp_unparse_packet_always(ctx, xf) != 0) {
        return DP_DROP;
    }

    if (xf->pm.pipe_act & F4_PIPE_RDR_MASK) {
      // if (dp_unparse_packet(ctx, xf) != 0) {
      //   return DP_DROP;
      // }
      // if (xf->pm.f4) {
      //   if (dp_f4_packet(ctx, xf) != 0) {
      //     return DP_DROP;
      //   }
      // }
      // return bpf_redirect(xf->pm.oport, BPF_F_INGRESS);
    }

  }
  return DP_PASS; /* FIXME */
}

static int __always_inline 
dp_ing_ct_main(void *ctx,  struct xfrm *xf)
{
  int val = 0;
  struct dp_fc_tacts *fa = NULL;

  fa = bpf_map_lookup_elem(&f4gw_fcas, &val);
  if (!fa) return DP_DROP;

  if (xf->pm.igr && (xf->pm.phit & F4_DP_CTM_HIT) == 0) {
    dp_do_nat(ctx, xf);
  }

  val = dp_ct_in(ctx, xf);
  if (val < 0) {
    return DP_PASS;
  }

  dp_l3_fwd(ctx, xf, fa);
  dp_eg_l2(ctx, xf, fa);

res_end:
  if (1) {
    int ret = dp_pipe_check_res(ctx, xf, fa);
    return ret;
  }
}

static int __always_inline
dp_ing_sh_main(void *ctx,  struct xfrm *xf)
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
  // if (xf->pm.mirr != 0) {
  //   dp_do_mirr_lkup(ctx, xf);
  //   goto out;
  // }

  // dp_ing(ctx, xf);

  /* If there are pipeline errors at this stage,
   * we again skip any further processing
   */
  if (xf->pm.pipe_act || xf->pm.tc == 0) {
    goto out;
  }

  dp_ing_l2(ctx, xf, fa);

  /* fast-cache is used only when certain conditions are met */
  if (F4_PIPE_FC_CAP(xf)) {
    fa->zone = xf->pm.zone;
    dp_insert_fcv4(ctx, xf, fa);
  }

out:
  bpf_tail_call(ctx, &f4gw_progs, F4_DP_CT_PGM_ID);
  return DP_PASS;
}

#endif