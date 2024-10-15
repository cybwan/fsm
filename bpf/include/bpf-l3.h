#ifndef __F4_BPF_L3_H__ 
#define __F4_BPF_L3_H__

#include "bpf-dbg.h"
#include "bpf-ct.h"
#include "bpf-lb.h"

static int __always_inline
dp_do_ctops(void *ctx, struct xpkt *pkt, void *fa_, 
             struct dp_ct_tact *act)
{
  struct dp_fc_tacts *fa = fa_;
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
    struct dp_fc_tact *ta = &fa->fcta[
                                  act->ca.act_type == DP_SET_SNAT ?
                                  DP_SET_SNAT : DP_SET_DNAT];
    ta->ca.act_type = act->ca.act_type;
    memcpy(&ta->nat_act,  &act->nat_act, sizeof(act->nat_act));

    na = &act->nat_act;

    if (pkt->pm.l4fin) {
      na->fr = 1;
    }

    dp_pipe_set_nat(ctx, pkt, na, act->ca.act_type == DP_SET_SNAT ? 1: 0);

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

  if (pkt->l34m.nw_proto == IPPROTO_TCP) {
    dp_run_ctact_helper(pkt, act);
  }

  return 0;

ct_trk:
  return dp_tail_call(ctx, pkt, fa_, F4_DP_CT_PGM_ID);
}

static int __always_inline
dp_do_ing_ct(void *ctx, struct xpkt *pkt, void *fa_)
{

  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, pkt);

  // pkt->pm.table_id = F4_DP_CT_MAP;
  act = bpf_map_lookup_elem(&f4gw_ct, &key);
  return dp_do_ctops(ctx, pkt, fa_, act);
}

static int __always_inline
dp_l3_fwd(void *ctx,  struct xpkt *pkt, void *fa)
{
  if (pkt->l2m.dl_type == htons(ETH_P_IP)) {
    if (pkt->pm.nf && pkt->nm.nv6 != 0) {
      pkt->nm.xlate_proto = 1;
      // dp_do_ipv6_fwd(ctx, pkt, fa);
    } else {
      // dp_do_ipv4_fwd(ctx, pkt, fa);
    }
  } else if (pkt->l2m.dl_type == htons(ETH_P_IPV6)) {
    if (pkt->pm.nf && pkt->nm.nv6 == 0) {
      pkt->nm.xlate_proto = 1;
      // dp_do_ipv4_fwd(ctx, pkt, fa);
    } else {
      // dp_do_ipv6_fwd(ctx, pkt, fa);
    }
  }
  return 0;
}

static int __always_inline
dp_ing_l3(void *ctx,  struct xpkt *pkt, void *fa)
{
  dp_do_ing_ct(ctx, pkt, fa);
  // dp_l3_fwd(ctx, pkt, fa);
  return 0;
}

#endif