#ifndef __F4_BPF_CT_H__
#define __F4_BPF_CT_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"
#include "bpf-dp.h"
#include "bpf-mdi.h"

#define dp_run_ctact_helper(x, a)                                              \
    do {                                                                       \
        switch ((a)->ca.act_type) {                                            \
        case DP_SET_NOP:                                                       \
        case DP_SET_SNAT:                                                      \
        case DP_SET_DNAT:                                                      \
            (a)->attr.pi.t.tcp_cts[CT_DIR_IN].pseq = (x)->l34.seq;             \
            (a)->attr.pi.t.tcp_cts[CT_DIR_IN].pack = (x)->l34.ack;             \
            break;                                                             \
        default:                                                               \
            break;                                                             \
        }                                                                      \
    } while (0)

INTERNAL(__u32)
dp_ct_get_newctr(__u32 *nid)
{
    __u32 k = 0;
    __u32 v = 0;
    struct dp_ct_ctrtact *ctr;

    ctr = bpf_map_lookup_elem(&fsm_ct_ctr, &k);

    if (ctr == NULL) {
        return 0;
    }

    *nid = ctr->start;
    /* FIXME - We can potentially do a percpu array and do away
     *         with the locking here
     */
    xpkt_spin_lock(&ctr->lock);
    v = ctr->counter;
    ctr->counter += 2;
    if (ctr->counter >= ctr->entries) {
        ctr->counter = ctr->start;
    }
    xpkt_spin_unlock(&ctr->lock);

    return v;
}

INTERNAL(int)
dp_ct_proto_xfk_init(xpkt_t *pkt, ct_key_t *ckey, nat_endpoint_t *cep,
                     ct_key_t *rkey, nat_endpoint_t *rep)
{
    XADDR_COPY(rkey->daddr, ckey->saddr);
    XADDR_COPY(rkey->saddr, ckey->daddr);
    rkey->sport = ckey->dport;
    rkey->dport = ckey->sport;
    rkey->proto = ckey->proto;
    rkey->v6 = ckey->v6;

    /* Apply NAT xfrm if needed */
    if (cep->nat_flags & F4_NAT_DST) {
        rkey->v6 = (__u8)(cep->nv6);
        XADDR_COPY(rkey->saddr, cep->nat_rip);
        // XADDR_COPY(rkey->daddr, cep->nat_xip);
        XADDR_COPY(rep->nat_xip, ckey->daddr);
        XADDR_COPY(rep->nat_rip, ckey->saddr);
        if (ckey->proto != IPPROTO_ICMP) {
            rkey->dport = cep->nat_xport;
            rkey->sport = cep->nat_rport;
            rep->nat_xport = ckey->dport;
            rep->nat_rport = ckey->sport;
        }

        rep->nat_flags = F4_NAT_SRC;
        rep->nv6 = ckey->v6;
    }
    if (cep->nat_flags & F4_NAT_SRC) {
        rkey->v6 = cep->nv6;
        // XADDR_COPY(rkey->saddr, cep->nat_rip);
        XADDR_COPY(rkey->daddr, cep->nat_xip);
        XADDR_COPY(rep->nat_rip, pkt->l34.saddr);
        XADDR_COPY(rep->nat_xip, pkt->l34.daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            rkey->dport = cep->nat_xport;
            rkey->sport = cep->nat_rport;
            rep->nat_xport = ckey->dport;
            rep->nat_rport = ckey->sport;
        }

        // rep->nat_xifi = pkt->ctx.ifi;
        rep->nat_flags = F4_NAT_DST;
        rep->nv6 = ckey->v6;

        // XMAC_COPY(rep->nat_xmac, pkt->l2m.dl_dst);
        // XMAC_COPY(rep->nat_rmac, pkt->l2m.dl_src);
    }
    if (cep->nat_flags & F4_NAT_HDST) {
        XADDR_COPY(rkey->saddr, ckey->saddr);
        XADDR_COPY(rkey->daddr, ckey->daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            if (cep->nat_xport)
                rkey->sport = cep->nat_xport;
            else
                cep->nat_xport = ckey->dport;
        }

        rep->nat_flags = F4_NAT_HSRC;
        rep->nv6 = ckey->v6;
        XADDR_SET_ZERO(rep->nat_xip);
        XADDR_SET_ZERO(cep->nat_xip);
        if (ckey->proto != IPPROTO_ICMP)
            rep->nat_xport = ckey->dport;
    }
    if (cep->nat_flags & F4_NAT_HSRC) {
        XADDR_COPY(rkey->saddr, ckey->saddr);
        XADDR_COPY(rkey->daddr, ckey->daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            if (cep->nat_xport)
                rkey->dport = cep->nat_xport;
            else
                cep->nat_xport = ckey->sport;
        }

        rep->nat_flags = F4_NAT_HDST;
        rep->nv6 = ckey->v6;
        XADDR_SET_ZERO(rep->nat_xip);
        XADDR_SET_ZERO(cep->nat_xip);

        if (ckey->proto != IPPROTO_ICMP)
            rep->nat_xport = ckey->sport;
    }

    return 0;
}

INTERNAL(int)
dp_ct_tcp_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *atdat, ct_op_t *axtdat,
             ct_dir_t dir)
{
    ct_attr_t *tdat = &atdat->attr;
    ct_attr_t *xtdat = &axtdat->attr;
    ct_tcp_sm_t *ts = &tdat->pi.t;
    ct_tcp_sm_t *rts = &xtdat->pi.t;
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));
    struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
    __u8 tcp_flags = pkt->ctx.tcp_flags;
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

    xpkt_spin_lock(&atdat->lock);

    if (dir == CT_DIR_IN) {
        tdat->pi.t.tcp_cts[0].pseq = t->seq;
        tdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    } else {
        xtdat->pi.t.tcp_cts[0].pseq = t->seq;
        xtdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    }

    rtd = &ts->tcp_cts[dir == CT_DIR_IN ? CT_DIR_OUT : CT_DIR_IN];

    if (tcp_flags & F4_TCP_RST) {
        nstate = CT_TCP_CLOSE_WAIT;
        goto end;
    }

    switch (ts->state) {
    case CT_TCP_CLOSED:
        /* If DP starts after TCP was established
         * we need to somehow handle this particular case
         */
        if (tcp_flags & F4_TCP_ACK) {
            td->seq = seq;
            if (td->init_acks) {
                if (ack > rtd->seq + 2) {
                    nstate = CT_TCP_ERR;
                    goto end;
                }
            }
            td->init_acks++;
            if (td->init_acks >= CT_TCP_INIT_ACK_THRESHOLD &&
                rtd->init_acks >= CT_TCP_INIT_ACK_THRESHOLD) {
                nstate = CT_TCP_ESTABLISHED;
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
        nstate = CT_TCP_SYN_SEND;
        break;
    case CT_TCP_SYN_SEND:
        if (dir != CT_DIR_OUT) {
            if ((tcp_flags & F4_TCP_SYN) == F4_TCP_SYN) {
                td->seq = seq;
                nstate = CT_TCP_SYN_SEND;
            } else {
                nstate = CT_TCP_ERR;
            }
            goto end;
        }

        if ((tcp_flags & (F4_TCP_SYN | F4_TCP_ACK)) !=
            (F4_TCP_SYN | F4_TCP_ACK)) {
            nstate = CT_TCP_ERR;
            goto end;
        }

        if (ack != rtd->seq + 1) {
            nstate = CT_TCP_ERR;
            goto end;
        }

        td->seq = seq;
        nstate = CT_TCP_SYN_ACK;
        break;

    case CT_TCP_SYN_ACK:
        if (dir != CT_DIR_IN) {
            if ((tcp_flags & (F4_TCP_SYN | F4_TCP_ACK)) !=
                (F4_TCP_SYN | F4_TCP_ACK)) {
                nstate = CT_TCP_ERR;
                goto end;
            }

            if (ack != rtd->seq + 1) {
                nstate = CT_TCP_ERR;
                goto end;
            }

            nstate = CT_TCP_SYN_ACK;
            goto end;
        }

        if ((tcp_flags & F4_TCP_SYN) == F4_TCP_SYN) {
            td->seq = seq;
            nstate = CT_TCP_SYN_SEND;
            goto end;
        }

        if ((tcp_flags & F4_TCP_ACK) != F4_TCP_ACK) {
            nstate = CT_TCP_ERR;
            goto end;
        }

        if (ack != rtd->seq + 1) {
            nstate = CT_TCP_ERR;
            goto end;
        }

        td->seq = seq;
        nstate = CT_TCP_ESTABLISHED;
        break;

    case CT_TCP_ESTABLISHED:
        if (tcp_flags & F4_TCP_FIN) {
            ts->fndir = dir;
            nstate = CT_TCP_FINI;
            td->seq = seq;
        } else {
            nstate = CT_TCP_ESTABLISHED;
        }
        break;

    case CT_TCP_FINI:
        if (ts->fndir != dir) {
            if ((tcp_flags & (F4_TCP_FIN | F4_TCP_ACK)) ==
                (F4_TCP_FIN | F4_TCP_ACK)) {
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
                nstate = CT_TCP_CLOSE_WAIT;
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

    xpkt_spin_unlock(&atdat->lock);

    if (nstate == CT_TCP_ESTABLISHED) {
        return CT_SMR_EST;
    } else if (nstate & CT_TCP_CLOSE_WAIT) {
        return CT_SMR_CTD;
    } else if (nstate & CT_TCP_ERR) {
        return CT_SMR_ERR;
    } else if (nstate & CT_TCP_FIN_MASK) {
        return CT_SMR_FIN;
    }

    return CT_SMR_INPROG;
}

INTERNAL(int)
dp_ct_udp_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *atdat, ct_op_t *axtdat,
             ct_dir_t dir)
{
    ct_attr_t *tdat = &atdat->attr;
    ct_attr_t *xtdat = &axtdat->attr;
    ct_udp_sm_t *us = &tdat->pi.u;
    ct_udp_sm_t *xus = &xtdat->pi.u;
    __u32 nstate = us->state;

    xpkt_spin_lock(&atdat->lock);

    switch (us->state) {
    case CT_UDP_CNI:
        if (pkt->l2.ssnid) {
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
        if (pkt->ctx.l4fin) {
            nstate = CT_UDP_FINI;
            us->fndir = dir;
        }
        break;
    case CT_UDP_FINI:
        if (pkt->ctx.l4fin && us->fndir != dir) {
            nstate = CT_UDP_CW;
        }
        break;
    default:
        break;
    }

    us->state = nstate;
    xus->state = nstate;

    xpkt_spin_unlock(&atdat->lock);

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

INTERNAL(int)
dp_ct_icmp_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *atdat, ct_op_t *axtdat,
              ct_dir_t dir)
{
    ct_attr_t *tdat = &atdat->attr;
    ct_attr_t *xtdat = &axtdat->attr;
    ct_icmp_sm_t *is = &tdat->pi.i;
    ct_icmp_sm_t *xis = &xtdat->pi.i;
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));
    struct icmphdr *i = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
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

    xpkt_spin_lock(&atdat->lock);

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

    xpkt_spin_unlock(&atdat->lock);

    if (nstate == CT_ICMP_REPS)
        return CT_SMR_EST;

    return CT_SMR_INPROG;
}

INTERNAL(int)
dp_ct_icmp6_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *atdat, ct_op_t *axtdat,
               ct_dir_t dir)
{
    ct_attr_t *tdat = &atdat->attr;
    ct_attr_t *xtdat = &axtdat->attr;
    ct_icmp_sm_t *is = &tdat->pi.i;
    ct_icmp_sm_t *xis = &xtdat->pi.i;
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));
    struct icmp6hdr *i = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
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

    xpkt_spin_lock(&atdat->lock);

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

    xpkt_spin_unlock(&atdat->lock);

    if (nstate == CT_ICMP_REPS)
        return CT_SMR_EST;

    return CT_SMR_INPROG;
}

INTERNAL(int)
dp_ct_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *atdat, ct_op_t *axtdat, ct_dir_t dir)
{
    int sm_ret = 0;

    switch (pkt->l34.proto) {
    case IPPROTO_TCP:
        sm_ret = dp_ct_tcp_sm(skb, pkt, atdat, axtdat, dir);
        break;
    case IPPROTO_UDP:
        sm_ret = dp_ct_udp_sm(skb, pkt, atdat, axtdat, dir);
        break;
    case IPPROTO_ICMP:
        sm_ret = dp_ct_icmp_sm(skb, pkt, atdat, axtdat, dir);
        break;
    case IPPROTO_ICMPV6:
        sm_ret = dp_ct_icmp6_sm(skb, pkt, atdat, axtdat, dir);
        break;
    default:
        sm_ret = CT_SMR_UNT;
        break;
    }

    return sm_ret;
}

#define CP_CT_NAT_TACTS(dst, src)                                              \
    memcpy(&dst->ca, &src->ca, sizeof(struct dp_cmn_act));                     \
    memcpy(&dst->attr, &src->attr, sizeof(ct_attr_t));                         \
    dst->ito = src->ito;                                                       \
    dst->lts = src->lts;                                                       \
    memcpy(&dst->nat_act, &src->nat_act, sizeof(struct dp_nat_act));

INTERNAL(int)
dp_ct_est(xpkt_t *pkt, ct_key_t *ckey, ct_key_t *rkey, ct_op_t *atdat,
          ct_op_t *axtdat)
{
    ct_attr_t *tdat = &atdat->attr;
    ct_op_t *cop, *rop;
    int i, j, k;

    k = 0;
    cop = bpf_map_lookup_elem(&fsm_ct_key, &k);

    k = 1;
    rop = bpf_map_lookup_elem(&fsm_ct_key, &k);

    if (cop == NULL || rop == NULL || tdat->ep.nv6) {
        return 0;
    }

    CP_CT_NAT_TACTS(cop, atdat);
    CP_CT_NAT_TACTS(rop, axtdat);

    switch (pkt->l34.proto) {
    case IPPROTO_UDP:
        if (pkt->l2.ssnid) {
            if (pkt->ctx.dir == CT_DIR_IN) {
                ckey->sport = pkt->l2.ssnid;
                ckey->dport = pkt->l2.ssnid;
                cop->attr.pi.frag = 1;
                bpf_map_update_elem(&fsm_ct, ckey, cop, BPF_ANY);
            } else {
                rkey->sport = pkt->l2.ssnid;
                rkey->dport = pkt->l2.ssnid;
                rop->attr.pi.frag = 1;
                bpf_map_update_elem(&fsm_ct, rkey, rop, BPF_ANY);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

INTERNAL(int)
dp_ct_del(xpkt_t *pkt, ct_key_t *ckey, ct_key_t *rkey, ct_op_t *atdat,
          ct_op_t *axtdat)
{
    return 0;
}

INTERNAL(int) dp_ct_in(skb_t *skb, xpkt_t *pkt)
{
    ct_key_t ckey;
    ct_key_t rkey;
    ct_op_t *cop;
    ct_op_t *rop;
    ct_op_t *atdat;
    ct_op_t *axtdat;
    nat_endpoint_t *cep;
    nat_endpoint_t *rep;
    int smr = CT_SMR_ERR;
    int k;

    if (F4_DEBUG_PKT(pkt)) {
        FSM_DBG("[DBG] dp_ct_in\n");
    }

    k = 0;
    cop = bpf_map_lookup_elem(&fsm_ct_key, &k);

    k = 1;
    rop = bpf_map_lookup_elem(&fsm_ct_key, &k);

    if (cop == NULL || rop == NULL) {
        return smr;
    }

    cep = &cop->attr.ep;
    rep = &rop->attr.ep;

    /* CT Key */
    XADDR_COPY(ckey.daddr, pkt->l34.daddr);
    XADDR_COPY(ckey.saddr, pkt->l34.saddr);
    ckey.sport = pkt->l34.source;
    ckey.dport = pkt->l34.dest;
    ckey.proto = pkt->l34.proto;
    ckey.v6 = pkt->l2.dl_type == ntohs(ETH_P_IPV6) ? 1 : 0;

    if (ckey.proto != IPPROTO_TCP && ckey.proto != IPPROTO_UDP &&
        ckey.proto != IPPROTO_ICMP && ckey.proto != IPPROTO_ICMPV6) {
        return CT_SMR_INPROG;
    }

    cep->nat_flags = pkt->ctx.nf;
    XADDR_COPY(cep->nat_xip, pkt->nat.nxip);
    XADDR_COPY(cep->nat_rip, pkt->nat.nrip);
    // XMAC_COPY(cep->nat_xmac, pkt->nm.nxmac);
    // XMAC_COPY(cep->nat_rmac, pkt->nm.nrmac);
    // cep->nat_xifi = pkt->nm.nxifi;
    cep->nat_xport = pkt->nat.nxport;
    cep->nat_rport = pkt->nat.nrport;
    cep->nv6 = pkt->nat.nv6;

    rep->nat_flags = 0;
    rep->nat_xport = 0;
    rep->nat_rport = 0;
    XADDR_SET_ZERO(rep->nat_xip);
    XADDR_SET_ZERO(rep->nat_rip);
    // XMAC_SET_ZERO(rep->nat_xmac);
    // XMAC_SET_ZERO(rep->nat_rmac);

    if (pkt->ctx.nf & (F4_NAT_DST | F4_NAT_SRC)) {
        if (XADDR_IS_ZERO(cep->nat_xip)) {
            if (pkt->ctx.nf == F4_NAT_DST) {
                cep->nat_flags = F4_NAT_HDST;
            } else if (pkt->ctx.nf == F4_NAT_SRC) {
                cep->nat_flags = F4_NAT_HSRC;
            }
        }
    }

    dp_ct_proto_xfk_init(pkt, &ckey, cep, &rkey, rep);

    atdat = bpf_map_lookup_elem(&fsm_ct, &ckey);
    axtdat = bpf_map_lookup_elem(&fsm_ct, &rkey);
    if (pkt->ctx.igr && (atdat == NULL || axtdat == NULL)) {
        cop->ca.ftrap = 0;
        cop->ca.oaux = 0;
        cop->ca.cidx = dp_ct_get_newctr(&cop->attr.nid);
        memset(&cop->attr.pi, 0, sizeof(ct_pinf_t));
        if (cep->nat_flags) {
            cop->ca.act_type = cep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                                   ? DP_SET_DNAT
                                   : DP_SET_SNAT;
            XADDR_COPY(cop->nat_act.xip, cep->nat_xip);
            XADDR_COPY(cop->nat_act.rip, cep->nat_rip);
            // XMAC_COPY(cop->nat_act.xmac,  cep->nat_xmac);
            // XMAC_COPY(cop->nat_act.rmac, cep->nat_rmac);
            // cop->nat_act.xifi = cep->nat_xifi;
            cop->nat_act.xport = cep->nat_xport;
            cop->nat_act.rport = cep->nat_rport;
            cop->nat_act.doct = 0;
            cop->nat_act.aid = pkt->nat.ep_sel;
            cop->nat_act.nv6 = pkt->nat.nv6 ? 1 : 0;
            cop->ito = pkt->nat.ito;
        } else {
            cop->ito = 0;
            cop->ca.act_type = DP_SET_DO_CT;
        }
        cop->attr.dir = CT_DIR_IN;

        /* FIXME This is duplicated data */
        cop->attr.rid = pkt->ctx.rule_id;
        cop->attr.aid = pkt->nat.ep_sel;
        cop->attr.smr = CT_SMR_INIT;

        rop->ca.ftrap = 0;
        rop->ca.oaux = 0;
        rop->ca.cidx = cop->ca.cidx + 1;
        rop->ca.record = pkt->ctx.dp_rec;
        memset(&rop->attr.pi, 0, sizeof(ct_pinf_t));
        if (rep->nat_flags) {
            rop->ca.act_type = rep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                                   ? DP_SET_DNAT
                                   : DP_SET_SNAT;
            XADDR_COPY(rop->nat_act.xip, rep->nat_xip);
            XADDR_COPY(rop->nat_act.rip, rep->nat_rip);
            // XMAC_COPY(rop->nat_act.xmac, rep->nat_xmac);
            // XMAC_COPY(rop->nat_act.rmac, rep->nat_rmac);
            // rop->nat_act.xifi = rep->nat_xifi;
            rop->nat_act.xport = rep->nat_xport;
            rop->nat_act.rport = rep->nat_rport;
            rop->nat_act.doct = 0;
            rop->nat_act.rid = pkt->ctx.rule_id;
            rop->nat_act.aid = pkt->nat.ep_sel;
            rop->nat_act.nv6 = ckey.v6 ? 1 : 0;
            rop->ito = pkt->nat.ito;
        } else {
            rop->ito = 0;
            rop->ca.act_type = DP_SET_DO_CT;
        }
        rop->lts = cop->lts;
        rop->attr.dir = CT_DIR_OUT;
        rop->attr.smr = CT_SMR_INIT;
        rop->attr.rid = cop->attr.rid;
        rop->attr.aid = cop->attr.aid;
        rop->attr.nid = cop->attr.nid;

        bpf_map_update_elem(&fsm_ct, &rkey, rop, BPF_ANY);
        bpf_map_update_elem(&fsm_ct, &ckey, cop, BPF_ANY);

        atdat = bpf_map_lookup_elem(&fsm_ct, &ckey);
        axtdat = bpf_map_lookup_elem(&fsm_ct, &rkey);
    }

    if (atdat != NULL && axtdat != NULL) {
        atdat->lts = bpf_ktime_get_ns();
        axtdat->lts = atdat->lts;
        pkt->ctx.act = F4_PIPE_RDR;
        if (atdat->attr.dir == CT_DIR_IN) {
            pkt->ctx.dir = CT_DIR_IN;
            pkt->ctx.phit |= F4_DP_CTSI_HIT;
            smr = dp_ct_sm(skb, pkt, atdat, axtdat, CT_DIR_IN);
        } else {
            pkt->ctx.dir = CT_DIR_OUT;
            pkt->ctx.phit |= F4_DP_CTSO_HIT;
            smr = dp_ct_sm(skb, pkt, axtdat, atdat, CT_DIR_OUT);
        }

        if (smr == CT_SMR_EST) {
            if (cep->nat_flags) {
                atdat->nat_act.doct = 0;
                axtdat->nat_act.doct = 0;
                if (atdat->attr.dir == CT_DIR_IN) {
                    dp_ct_est(pkt, &ckey, &rkey, atdat, axtdat);
                } else {
                    dp_ct_est(pkt, &rkey, &ckey, axtdat, atdat);
                }
            } else {
                atdat->ca.act_type = DP_SET_NOP;
                axtdat->ca.act_type = DP_SET_NOP;
            }
        } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
            bpf_map_delete_elem(&fsm_ct, &rkey);
            bpf_map_delete_elem(&fsm_ct, &ckey);
            // F4_DBG_PRINTK("[CTRK] bpf_map_delete_elem");

            if (atdat->attr.dir == CT_DIR_IN) {
                dp_ct_del(pkt, &ckey, &rkey, atdat, axtdat);
            } else {
                dp_ct_del(pkt, &rkey, &ckey, axtdat, atdat);
            }

            if (cep->nat_flags) {
                // dp_do_dec_nat_sess(skb, xf, atdat->attr.rid,
                // atdat->attr.aid);
            }
        }
    }

    return smr;
}

#endif