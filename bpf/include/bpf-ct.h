#ifndef __F4_BPF_CT_H__ 
#define __F4_BPF_CT_H__

#include "bpf-dbg.h"
#include "bpf-dp.h"
#include "bpf-mdi.h"

#define CT_KEY_GEN(k, xf)                    \
do {                                         \
  (k)->daddr[0] = pkt->l34.daddr[0];         \
  (k)->daddr[1] = pkt->l34.daddr[1];         \
  (k)->daddr[2] = pkt->l34.daddr[2];         \
  (k)->daddr[3] = pkt->l34.daddr[3];         \
  (k)->saddr[0] = pkt->l34.saddr[0];         \
  (k)->saddr[1] = pkt->l34.saddr[1];         \
  (k)->saddr[2] = pkt->l34.saddr[2];         \
  (k)->saddr[3] = pkt->l34.saddr[3];         \
  (k)->sport = pkt->l34.source;              \
  (k)->dport = pkt->l34.dest;                \
  (k)->l4proto = pkt->l34.nw_proto;          \
  (k)->zone = pkt->pm.zone;                   \
  (k)->v6 = pkt->l2.dl_type == ntohs(ETH_P_IPV6) ? 1: 0; \
}while(0)

#define dp_run_ctact_helper(x, a) \
do {                              \
  switch ((a)->ca.act_type) {     \
  case DP_SET_NOP:                \
  case DP_SET_SNAT:               \
  case DP_SET_DNAT:               \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pseq = (x)->l34.seq;   \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pack = (x)->l34.ack;   \
    break;                        \
  default:                        \
    break;                        \
  }                               \
} while(0)

static __u32 __always_inline
dp_ct_get_newctr(__u32 *nid)
{
  __u32 k = 0;
  __u32 v = 0;
  struct dp_ct_ctrtact *ctr;

  ctr = bpf_map_lookup_elem(&f4gw_ct_ctr, &k);

  if (ctr == NULL) {
    return 0;
  }

  *nid = ctr->start;
  /* FIXME - We can potentially do a percpu array and do away
   *         with the locking here
   */ 
  dp_spin_lock(&ctr->lock);
  v = ctr->counter;
  ctr->counter += 2;
  if (ctr->counter >= ctr->entries) {
    ctr->counter = ctr->start;
  }
  dp_spin_unlock(&ctr->lock);

  return v;
}

static int __always_inline
dp_ct_proto_xfk_init(struct xpkt *pkt,
                     struct dp_ct_key *key,
                     nxfrm_inf_t *xi,
                     struct dp_ct_key *xkey,
                     nxfrm_inf_t *xxi)
{
  XADDR_COPY(xkey->daddr, key->saddr);
  XADDR_COPY(xkey->saddr, key->daddr);
  xkey->sport = key->dport; 
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;

  if (xi->dsr) {
    if (xi->nat_flags & F4_NAT_DST) {
      xxi->nat_flags = F4_NAT_SRC;
      XADDR_COPY(xxi->nat_xip, key->daddr);
      xxi->nat_xport = key->dport;
      xxi->nv6 = xi->nv6;
    }
    xxi->dsr = xi->dsr;
    return 0;
  }

  /* Apply NAT xfrm if needed */
  if (xi->nat_flags & F4_NAT_DST) {
    xkey->v6 = (__u8)(xi->nv6);
    XADDR_COPY(xkey->saddr, xi->nat_rip);
    // XADDR_COPY(xkey->daddr, xi->nat_xip);
    XADDR_COPY(xxi->nat_xip, key->daddr);
    XADDR_COPY(xxi->nat_rip, key->saddr);
    if (key->l4proto != IPPROTO_ICMP) {
      xkey->dport = xi->nat_xport;
      xkey->sport = xi->nat_rport;
      xxi->nat_xport = key->dport;
      xxi->nat_rport = key->sport;
    }

    xxi->nat_flags = F4_NAT_SRC;
    xxi->nv6 = key->v6;
  }
  if (xi->nat_flags & F4_NAT_SRC) {
    xkey->v6 = xi->nv6;
    // XADDR_COPY(xkey->saddr, xi->nat_rip);
    XADDR_COPY(xkey->daddr, xi->nat_xip);
    XADDR_COPY(xxi->nat_rip, pkt->l34.saddr);
    XADDR_COPY(xxi->nat_xip, pkt->l34.daddr);
    
    if (key->l4proto != IPPROTO_ICMP) {
      xkey->dport = xi->nat_xport;
      xkey->sport = xi->nat_rport;
      xxi->nat_xport = key->dport;
      xxi->nat_rport = key->sport;
    }

    // xxi->nat_xifi = pkt->pm.ifi;
    xxi->nat_flags = F4_NAT_DST;
    xxi->nv6 = key->v6;
    
    // DP_XMAC_CP(xxi->nat_xmac, pkt->l2m.dl_dst);
    // DP_XMAC_CP(xxi->nat_rmac, pkt->l2m.dl_src);
  }
  if (xi->nat_flags & F4_NAT_HDST) {
    XADDR_COPY(xkey->saddr, key->saddr);
    XADDR_COPY(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->sport = xi->nat_xport;
      else
        xi->nat_xport = key->dport;
    }

    xxi->nat_flags = F4_NAT_HSRC;
    xxi->nv6 = key->v6;
    XADDR_SET_ZERO(xxi->nat_xip);
    XADDR_SET_ZERO(xi->nat_xip);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & F4_NAT_HSRC) {
    XADDR_COPY(xkey->saddr, key->saddr);
    XADDR_COPY(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = F4_NAT_HDST;
    xxi->nv6 = key->v6;
    XADDR_SET_ZERO(xxi->nat_xip);
    XADDR_SET_ZERO(xi->nat_xip);

    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }

  return 0;  
}

static int __always_inline
dp_ct_tcp_sm(void *ctx, struct xpkt *pkt, 
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_tcp_pinf_t *ts = &tdat->pi.t;
  ct_tcp_pinf_t *rts = &xtdat->pi.t;
  void *dend = TC_PTR(FSM_PKT_DATA_END(ctx));
  struct tcphdr *t = TC_PTR_ADD(FSM_PKT_DATA(ctx), pkt->pm.l4_off);
  __u8 tcp_flags = pkt->pm.tcp_flags;
  ct_tcp_pinfd_t *td = &ts->tcp_cts[dir];
  ct_tcp_pinfd_t *rtd;
  __u32 seq;
  __u32 ack;
  __u32 nstate = 0;

  if ((void *)(t + 1) > dend) {
    F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLCT_ERR);
    return -1;
  }

  seq = ntohl(t->seq);
  ack = ntohl(t->ack_seq);

  dp_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pi.t.tcp_cts[0].pseq = t->seq;
    tdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    tdat->pb.bytes += pkt->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pi.t.tcp_cts[0].pseq = t->seq;
    xtdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    xtdat->pb.bytes += pkt->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  rtd = &ts->tcp_cts[dir == CT_DIR_IN ? CT_DIR_OUT:CT_DIR_IN];

  if (tcp_flags & F4_TCP_RST) {
    nstate = CT_TCP_CW;
    goto end;
  }

  switch (ts->state) {
  case CT_TCP_CLOSED:

    if (pkt->nat.dsr) {
      nstate = CT_TCP_EST;
      goto end;
    }

    /* If DP starts after TCP was established
     * we need to somehow handle this particular case
     */
    if (tcp_flags & F4_TCP_ACK)  {
      td->seq = seq;
      if (td->init_acks) {
        if (ack  > rtd->seq + 2) {
          nstate = CT_TCP_ERR;
          goto end;
        }
      }
      td->init_acks++;
      if (td->init_acks >= CT_TCP_INIT_ACK_THRESHOLD &&
          rtd->init_acks >= CT_TCP_INIT_ACK_THRESHOLD) {
        nstate = CT_TCP_EST;
        break;
      }
      nstate = CT_TCP_ERR;
      goto end;
    }
    
    if ((tcp_flags & F4_TCP_SYN) != F4_TCP_SYN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    /* SYN sent with ack 0 */
    if (ack != 0 && dir != CT_DIR_IN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SS;
    break;
  case CT_TCP_SS:
    if (dir != CT_DIR_OUT) {
      if ((tcp_flags & F4_TCP_SYN) == F4_TCP_SYN) {
        td->seq = seq;
        nstate = CT_TCP_SS;
      } else {
        nstate = CT_TCP_ERR;
      }
      goto end;
    }
  
    if ((tcp_flags & (F4_TCP_SYN|F4_TCP_ACK)) !=
         (F4_TCP_SYN|F4_TCP_ACK)) {
      nstate = CT_TCP_ERR;
      goto end;
    }
  
    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SA;
    break;

  case CT_TCP_SA:
    if (dir != CT_DIR_IN) {
      if ((tcp_flags & (F4_TCP_SYN|F4_TCP_ACK)) !=
         (F4_TCP_SYN|F4_TCP_ACK)) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      if (ack  != rtd->seq + 1) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      nstate = CT_TCP_SA;
      goto end;
    } 

    if ((tcp_flags & F4_TCP_SYN) == F4_TCP_SYN) {
      td->seq = seq;
      nstate = CT_TCP_SS;
      goto end;
    }
  
    if ((tcp_flags & F4_TCP_ACK) != F4_TCP_ACK) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_EST;
    break;

  case CT_TCP_EST:
    if (tcp_flags & F4_TCP_FIN) {
      ts->fndir = dir;
      nstate = CT_TCP_FINI;
      td->seq = seq;
    } else {
      nstate = CT_TCP_EST;
    }
    break;

  case CT_TCP_FINI:
    if (ts->fndir != dir) {
      if ((tcp_flags & (F4_TCP_FIN|F4_TCP_ACK)) == 
          (F4_TCP_FIN|F4_TCP_ACK)) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      } else if (tcp_flags & F4_TCP_ACK) {
        nstate = CT_TCP_FINI2;
        td->seq = seq;
      }
    }
    break;
  case CT_TCP_FINI2:
    if (ts->fndir != dir) {
      if (tcp_flags & F4_TCP_FIN) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      }
    }
    break;

  case CT_TCP_FINI3:
    if (ts->fndir == dir) {
      if (tcp_flags & F4_TCP_ACK) {
        nstate = CT_TCP_CW;
      }
    }
    break;

  default:
    break;
  }

end:
  ts->state = nstate;
  rts->state = nstate;

  if (nstate != CT_TCP_ERR && dir == CT_DIR_OUT) {
    xtdat->pi.t.tcp_cts[0].seq = seq;
  }

  dp_spin_unlock(&atdat->lock);

  if (nstate == CT_TCP_EST) {
    return CT_SMR_EST;
  } else if (nstate & CT_TCP_CW) {
    return CT_SMR_CTD;
  } else if (nstate & CT_TCP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_TCP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_udp_sm(void *ctx, struct xpkt *pkt,
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_udp_pinf_t *us = &tdat->pi.u;
  ct_udp_pinf_t *xus = &xtdat->pi.u;
  __u32 nstate = us->state;

  dp_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += pkt->pm.l3_len;
    tdat->pb.packets += 1;
    us->pkts_seen++;
  } else {
    xtdat->pb.bytes += pkt->pm.l3_len;
    xtdat->pb.packets += 1;
    us->rpkts_seen++;
  }

  switch (us->state) {
  case CT_UDP_CNI:

    if (pkt->nat.dsr || pkt->l2.ssnid) {
      nstate = CT_UDP_EST;
      break;
    }

    if (us->pkts_seen && us->rpkts_seen) {
      nstate = CT_UDP_EST;
    } else if (us->pkts_seen > CT_UDP_CONN_THRESHOLD) {
      nstate = CT_UDP_UEST;
    }

    break;
  case CT_UDP_UEST:
    if (us->rpkts_seen)
      nstate = CT_UDP_EST;
    break;
  case CT_UDP_EST:
    if (pkt->pm.l4fin) {
      nstate = CT_UDP_FINI;
      us->fndir = dir;
    }
    break;
  case CT_UDP_FINI:
    if (pkt->pm.l4fin && us->fndir != dir) {
      nstate = CT_UDP_CW;
    }
    break;
  default:
    break;
  }

  us->state = nstate;
  xus->state = nstate;

  dp_spin_unlock(&atdat->lock);

  if (nstate == CT_UDP_UEST)
    return CT_SMR_UEST;
  else if (nstate == CT_UDP_EST)
    return CT_SMR_EST;
  else if (nstate & CT_UDP_CW)
    return CT_SMR_CTD;
  else if (nstate & CT_UDP_FIN_MASK)
    return CT_SMR_FIN;

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_icmp_sm(void *ctx, struct xpkt *pkt, 
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = TC_PTR(FSM_PKT_DATA_END(ctx));
  struct icmphdr *i = TC_PTR_ADD(FSM_PKT_DATA(ctx), pkt->pm.l4_off);
  __u32 nstate;
  __u16 seq;

  if ((void *)(i + 1) > dend) {
    F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLCT_ERR);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = ntohs(i->un.echo.sequence);

  dp_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += pkt->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += pkt->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->type) {
  case ICMP_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMP_TIME_EXCEEDED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMP_REDIRECT:
    is->state |= CT_ICMP_RDR;
    goto end;
  case ICMP_ECHOREPLY:
  case ICMP_ECHO:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  } 

  switch (is->state) { 
  case CT_ICMP_CLOSED: 
    if (pkt->nat.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }

    if (i->type != ICMP_ECHO) { 
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->type == ICMP_ECHO) {
      is->lseq = seq;
    } else if (i->type == ICMP_ECHOREPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

  dp_spin_unlock(&atdat->lock);

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_icmp6_sm(void *ctx, struct xpkt *pkt,
               struct dp_ct_tact *atdat,
               struct dp_ct_tact *axtdat,
               ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = TC_PTR(FSM_PKT_DATA_END(ctx));
  struct icmp6hdr *i = TC_PTR_ADD(FSM_PKT_DATA(ctx), pkt->pm.l4_off);
  __u32 nstate;
  __u16 seq;

  if ((void *)(i + 1) > dend) {
    F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLCT_ERR);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = ntohs(i->icmp6_dataun.u_echo.sequence);

  dp_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += pkt->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += pkt->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->icmp6_type) {
  case ICMPV6_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMPV6_TIME_EXCEED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMPV6_ECHO_REPLY:
  case ICMPV6_ECHO_REQUEST:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  }

  switch (is->state) {
  case CT_ICMP_CLOSED:
    if (pkt->nat.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }
    if (i->icmp6_type != ICMPV6_ECHO_REQUEST) {
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->icmp6_type == ICMPV6_ECHO_REQUEST) {
      is->lseq = seq;
    } else if (i->icmp6_type == ICMPV6_ECHO_REPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

  dp_spin_unlock(&atdat->lock);

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}


static int __always_inline
dp_ct_sm(void *ctx, struct xpkt *pkt,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat,
         ct_dir_t dir)
{
  int sm_ret = 0;

  switch (pkt->l34.nw_proto) {
  case IPPROTO_TCP:
    sm_ret = dp_ct_tcp_sm(ctx, pkt, atdat, axtdat, dir);
    break;
  case IPPROTO_UDP:
    sm_ret = dp_ct_udp_sm(ctx, pkt, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMP:
    sm_ret = dp_ct_icmp_sm(ctx, pkt, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMPV6:
    sm_ret = dp_ct_icmp6_sm(ctx, pkt, atdat, axtdat, dir);
    break;
  default:
    sm_ret = CT_SMR_UNT;
    break;
  }

  return sm_ret;
}

#define CP_CT_NAT_TACTS(dst, src)  \
  memcpy(&dst->ca, &src->ca, sizeof(struct dp_cmn_act));  \
  memcpy(&dst->ctd, &src->ctd, sizeof(struct dp_ct_dat)); \
  dst->ito =  src->ito; \
  dst->lts =  src->lts; \
  memcpy(&dst->nat_act, &src->nat_act, sizeof(struct dp_nat_act)); \

static int __always_inline
dp_ct_est(struct xpkt *pkt,
         struct dp_ct_key *key,
         struct dp_ct_key *xkey,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_tact *adat, *axdat;
  int i, j, k;

  k = 0;
  adat = bpf_map_lookup_elem(&f4gw_xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&f4gw_xctk, &k);

  if (adat == NULL || axdat == NULL || tdat->xi.dsr || tdat->xi.nv6) {
    return 0;
  }

  CP_CT_NAT_TACTS(adat, atdat);
  CP_CT_NAT_TACTS(axdat, axtdat);

  switch (pkt->l34.nw_proto) {
  case IPPROTO_UDP:
    if (pkt->l2.ssnid) {
      if (pkt->pm.dir == CT_DIR_IN) {
        adat->ctd.xi.osp = key->sport;
        adat->ctd.xi.odp = key->dport;
        key->sport = pkt->l2.ssnid;
        key->dport = pkt->l2.ssnid;
        adat->ctd.pi.frag = 1;
        bpf_map_update_elem(&f4gw_ct, key, adat, BPF_ANY);
      } else {
        axdat->ctd.xi.osp = xkey->sport;
        axdat->ctd.xi.odp = xkey->dport;
        xkey->sport = pkt->l2.ssnid;
        xkey->dport = pkt->l2.ssnid;
        axdat->ctd.pi.frag = 1;
        bpf_map_update_elem(&f4gw_ct, xkey, axdat, BPF_ANY);
      }
    }
    break;
  default:
    break;
  }
  return 0;
}

static int __always_inline
dp_ct_del(struct xpkt *pkt,
         struct dp_ct_key *key,
         struct dp_ct_key *xkey,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat)
{
  return 0;
}

static int __always_inline
dp_ct_in(void *ctx, struct xpkt *pkt)
{
  struct dp_ct_key key;
  struct dp_ct_key xkey;
  struct dp_ct_tact *adat;
  struct dp_ct_tact *axdat;
  struct dp_ct_tact *atdat;
  struct dp_ct_tact *axtdat;
  nxfrm_inf_t *xi;
  nxfrm_inf_t *xxi;
  int smr = CT_SMR_ERR;
  int k;

  k = 0;
  adat = bpf_map_lookup_elem(&f4gw_xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&f4gw_xctk, &k);

  if (adat == NULL || axdat == NULL) {
    return smr;
  }

  xi = &adat->ctd.xi;
  xxi = &axdat->ctd.xi;
 
  /* CT Key */
  XADDR_COPY(key.daddr, pkt->l34.daddr);
  XADDR_COPY(key.saddr, pkt->l34.saddr);
  key.sport = pkt->l34.source;
  key.dport = pkt->l34.dest;
  key.l4proto = pkt->l34.nw_proto;
  key.zone = pkt->pm.zone;
  key.v6 = pkt->l2.dl_type == ntohs(ETH_P_IPV6) ? 1: 0;

  if (key.l4proto != IPPROTO_TCP &&
      key.l4proto != IPPROTO_UDP &&
      key.l4proto != IPPROTO_ICMP &&
      key.l4proto != IPPROTO_ICMPV6) {
    return CT_SMR_INPROG;
  }

  xi->nat_flags = pkt->pm.nf;
  XADDR_COPY(xi->nat_xip, pkt->nat.nxip);
  XADDR_COPY(xi->nat_rip, pkt->nat.nrip);
  // DP_XMAC_CP(xi->nat_xmac, pkt->nm.nxmac);
  // DP_XMAC_CP(xi->nat_rmac, pkt->nm.nrmac);
  // xi->nat_xifi = pkt->nm.nxifi;
  xi->nat_xport = pkt->nat.nxport;
  xi->nat_rport = pkt->nat.nrport;
  xi->nv6 = pkt->nat.nv6;
  xi->dsr = pkt->nat.dsr;

  xxi->nat_flags = 0;
  xxi->nat_xport = 0;
  xxi->nat_rport = 0;
  XADDR_SET_ZERO(xxi->nat_xip);
  XADDR_SET_ZERO(xxi->nat_rip);
  // DP_XMAC_SETZR(xxi->nat_xmac);
  // DP_XMAC_SETZR(xxi->nat_rmac);

  if (pkt->pm.nf & (F4_NAT_DST|F4_NAT_SRC)) {
    if (XADDR_IS_ZERO(xi->nat_xip)) {
      if (pkt->pm.nf == F4_NAT_DST) {
        xi->nat_flags = F4_NAT_HDST;
      } else if (pkt->pm.nf == F4_NAT_SRC){
        xi->nat_flags = F4_NAT_HSRC;
      }
    }
  }

  dp_ct_proto_xfk_init(pkt, &key, xi, &xkey, xxi);

  atdat = bpf_map_lookup_elem(&f4gw_ct, &key);
  axtdat = bpf_map_lookup_elem(&f4gw_ct, &xkey);
  if (pkt->pm.igr && (atdat == NULL || axtdat == NULL)) {
    adat->ca.ftrap = 0;
    adat->ca.oaux = 0;
    adat->ca.cidx = dp_ct_get_newctr(&adat->ctd.nid);
    memset(&adat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xi->nat_flags) {
      adat->ca.act_type = xi->nat_flags & (F4_NAT_DST|F4_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      XADDR_COPY(adat->nat_act.xip,  xi->nat_xip);
      XADDR_COPY(adat->nat_act.rip, xi->nat_rip);
      // DP_XMAC_CP(adat->nat_act.xmac,  xi->nat_xmac);
      // DP_XMAC_CP(adat->nat_act.rmac, xi->nat_rmac);
      // adat->nat_act.xifi = xi->nat_xifi;
      adat->nat_act.xport = xi->nat_xport;
      adat->nat_act.rport = xi->nat_rport;
      adat->nat_act.doct = 0;
      adat->nat_act.aid = pkt->nat.sel_aid;
      adat->nat_act.nv6 = pkt->nat.nv6 ? 1:0;
      adat->nat_act.dsr = pkt->nat.dsr;
      adat->nat_act.cdis = pkt->nat.cdis;
      adat->ito = pkt->nat.ito;
    } else {
      adat->ito = 0;
      adat->ca.act_type = DP_SET_DO_CT;
    }
    adat->ctd.dir = CT_DIR_IN;

    /* FIXME This is duplicated data */
    adat->ctd.rid = pkt->pm.rule_id;
    adat->ctd.aid = pkt->nat.sel_aid;
    adat->ctd.smr = CT_SMR_INIT;
    adat->ctd.pb.bytes = 0;
    adat->ctd.pb.packets = 0;

    axdat->ca.ftrap = 0;
    axdat->ca.oaux = 0;
    axdat->ca.cidx = adat->ca.cidx + 1;
    axdat->ca.record = pkt->pm.dp_rec;
    memset(&axdat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xxi->nat_flags) { 
      axdat->ca.act_type = xxi->nat_flags & (F4_NAT_DST|F4_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      XADDR_COPY(axdat->nat_act.xip, xxi->nat_xip);
      XADDR_COPY(axdat->nat_act.rip, xxi->nat_rip);
      // DP_XMAC_CP(axdat->nat_act.xmac, xxi->nat_xmac);
      // DP_XMAC_CP(axdat->nat_act.rmac, xxi->nat_rmac);
      // axdat->nat_act.xifi = xxi->nat_xifi;
      axdat->nat_act.xport = xxi->nat_xport;
      axdat->nat_act.rport = xxi->nat_rport;
      axdat->nat_act.doct = 0;
      axdat->nat_act.rid = pkt->pm.rule_id;
      axdat->nat_act.aid = pkt->nat.sel_aid;
      axdat->nat_act.nv6 = key.v6 ? 1:0;
      axdat->nat_act.dsr = pkt->nat.dsr;
      axdat->nat_act.cdis = pkt->nat.cdis;
      axdat->ito = pkt->nat.ito;
    } else {
      axdat->ito = 0;
      axdat->ca.act_type = DP_SET_DO_CT;
    }
    axdat->lts = adat->lts;
    axdat->ctd.dir = CT_DIR_OUT;
    axdat->ctd.smr = CT_SMR_INIT;
    axdat->ctd.rid = adat->ctd.rid;
    axdat->ctd.aid = adat->ctd.aid;
    axdat->ctd.nid = adat->ctd.nid;
    axdat->ctd.pb.bytes = 0;
    axdat->ctd.pb.packets = 0;

    bpf_map_update_elem(&f4gw_ct, &xkey, axdat, BPF_ANY);
    bpf_map_update_elem(&f4gw_ct, &key, adat, BPF_ANY);

    atdat = bpf_map_lookup_elem(&f4gw_ct, &key);
    axtdat = bpf_map_lookup_elem(&f4gw_ct, &xkey);
  }

  if (atdat != NULL && axtdat != NULL) {
    atdat->lts = bpf_ktime_get_ns();
    axtdat->lts = atdat->lts;
    pkt->pm.pipe_act = F4_PIPE_RDR;
    if (atdat->ctd.dir == CT_DIR_IN) {
      pkt->pm.dir = CT_DIR_IN;
      pkt->pm.phit |= F4_DP_CTSI_HIT;
      smr = dp_ct_sm(ctx, pkt, atdat, axtdat, CT_DIR_IN);
    } else {
      pkt->pm.dir = CT_DIR_OUT;
      pkt->pm.phit |= F4_DP_CTSO_HIT;
      smr = dp_ct_sm(ctx, pkt, axtdat, atdat, CT_DIR_OUT);
    }

    if (smr == CT_SMR_EST) {
      if (xi->nat_flags) {
        atdat->nat_act.doct = 0;
        axtdat->nat_act.doct = 0;
        if (atdat->ctd.dir == CT_DIR_IN) {
          dp_ct_est(pkt, &key, &xkey, atdat, axtdat);
        } else {
          dp_ct_est(pkt, &xkey, &key, axtdat, atdat);
        }
      } else {
        atdat->ca.act_type = DP_SET_NOP;
        axtdat->ca.act_type = DP_SET_NOP;
      }
    } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
      bpf_map_delete_elem(&f4gw_ct, &xkey);
      bpf_map_delete_elem(&f4gw_ct, &key);
      // F4_DBG_PRINTK("[CTRK] bpf_map_delete_elem");

      if (atdat->ctd.dir == CT_DIR_IN) {
        dp_ct_del(pkt, &key, &xkey, atdat, axtdat);
      } else {
        dp_ct_del(pkt, &xkey, &key, axtdat, atdat);
      }

      if (xi->nat_flags) {
        // dp_do_dec_nat_sess(ctx, xf, atdat->ctd.rid, atdat->ctd.aid);
      }
    }
  }

  return smr;
}

#endif