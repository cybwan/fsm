#ifndef __F4_BPF_CT_H__
#define __F4_BPF_CT_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"
#include "bpf-dp.h"
#include "bpf-mdi.h"

#define dp_run_ctact_helper(x, a)                                              \
    do {                                                                       \
        switch ((a)->act_type) {                                               \
        case NF_DO_NOOP:                                                       \
        case NF_DO_SNAT:                                                       \
        case NF_DO_DNAT:                                                       \
            (a)->attr.sm.t.dirs[CT_DIR_IN].pseq = (x)->l34.seq;                \
            (a)->attr.sm.t.dirs[CT_DIR_IN].pack = (x)->l34.ack_seq;            \
            break;                                                             \
        default:                                                               \
            break;                                                             \
        }                                                                      \
    } while (0)

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
dp_ct_tcp_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *caop, ct_op_t *raop,
             ct_dir_t dir)
{
    ct_attr_t *tdat = &caop->attr;
    ct_attr_t *xtdat = &raop->attr;
    ct_tcp_sm_t *ts = &tdat->sm.t;
    ct_tcp_sm_t *rts = &xtdat->sm.t;
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));
    struct tcphdr *t = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
    __u8 tcp_flags = pkt->ctx.tcp_flags;
    ct_tcp_sm_dir_t *td = &ts->dirs[dir];
    ct_tcp_sm_dir_t *rtd;
    __u32 seq, ack_seq;
    __u32 nstate = 0;

    if ((void *)(t + 1) > dend) {
        F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLCT_ERR);
        return -1;
    }

    seq = ntohl(t->seq);
    ack_seq = ntohl(t->ack_seq);

    xpkt_spin_lock(&caop->lock);

    if (dir == CT_DIR_IN) {
        tdat->sm.t.dirs[0].pseq = t->seq;
        tdat->sm.t.dirs[0].pack = t->ack_seq;
    } else {
        xtdat->sm.t.dirs[0].pseq = t->seq;
        xtdat->sm.t.dirs[0].pack = t->ack_seq;
    }

    rtd = &ts->dirs[dir == CT_DIR_IN ? CT_DIR_OUT : CT_DIR_IN];

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
                if (ack_seq > rtd->seq + 2) {
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

        /* SYN sent with ack_seq 0 */
        if (ack_seq != 0 && dir != CT_DIR_IN) {
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

        if (ack_seq != rtd->seq + 1) {
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

            if (ack_seq != rtd->seq + 1) {
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

        if (ack_seq != rtd->seq + 1) {
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
        xtdat->sm.t.dirs[0].seq = seq;
    }

    xpkt_spin_unlock(&caop->lock);

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
dp_ct_udp_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *caop, ct_op_t *raop,
             ct_dir_t dir)
{
    ct_attr_t *tdat = &caop->attr;
    ct_attr_t *xtdat = &raop->attr;
    ct_udp_sm_t *us = &tdat->sm.u;
    ct_udp_sm_t *xus = &xtdat->sm.u;
    __u32 nstate = us->state;

    xpkt_spin_lock(&caop->lock);

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

    xpkt_spin_unlock(&caop->lock);

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
dp_ct_icmp_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *caop, ct_op_t *raop,
              ct_dir_t dir)
{
    ct_attr_t *tdat = &caop->attr;
    ct_attr_t *xtdat = &raop->attr;
    ct_icmp_sm_t *is = &tdat->sm.i;
    ct_icmp_sm_t *xis = &xtdat->sm.i;
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

    xpkt_spin_lock(&caop->lock);

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

    xpkt_spin_unlock(&caop->lock);

    if (nstate == CT_ICMP_REPS)
        return CT_SMR_EST;

    return CT_SMR_INPROG;
}

INTERNAL(int)
dp_ct_icmp6_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *caop, ct_op_t *raop,
               ct_dir_t dir)
{
    ct_attr_t *tdat = &caop->attr;
    ct_attr_t *xtdat = &raop->attr;
    ct_icmp_sm_t *is = &tdat->sm.i;
    ct_icmp_sm_t *xis = &xtdat->sm.i;
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

    xpkt_spin_lock(&caop->lock);

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

    xpkt_spin_unlock(&caop->lock);

    if (nstate == CT_ICMP_REPS)
        return CT_SMR_EST;

    return CT_SMR_INPROG;
}

INTERNAL(int)
dp_ct_sm(skb_t *skb, xpkt_t *pkt, ct_op_t *caop, ct_op_t *raop, ct_dir_t dir)
{
    int sm_ret = 0;

    switch (pkt->l34.proto) {
    case IPPROTO_TCP:
        sm_ret = dp_ct_tcp_sm(skb, pkt, caop, raop, dir);
        break;
    case IPPROTO_UDP:
        sm_ret = dp_ct_udp_sm(skb, pkt, caop, raop, dir);
        break;
    case IPPROTO_ICMP:
        sm_ret = dp_ct_icmp_sm(skb, pkt, caop, raop, dir);
        break;
    case IPPROTO_ICMPV6:
        sm_ret = dp_ct_icmp6_sm(skb, pkt, caop, raop, dir);
        break;
    default:
        sm_ret = CT_SMR_UNT;
        break;
    }

    return sm_ret;
}

#define CP_CT_NAT_TACTS(dst, src)                                              \
    memcpy(&dst->attr, &src->attr, sizeof(ct_attr_t));                         \
    dst->ito = src->ito;                                                       \
    dst->lts = src->lts;                                                       \
    memcpy(&dst->nat_act, &src->nat_act, sizeof(struct dp_nat_act));

INTERNAL(int)
dp_ct_est(xpkt_t *pkt, ct_key_t *ckey, ct_key_t *rkey, ct_op_t *caop,
          ct_op_t *raop)
{
    ct_attr_t *tdat = &caop->attr;
    ct_op_t *cuop, *ruop;
    int i, j, k;

    k = 0;
    cuop = bpf_map_lookup_elem(&fsm_ct_ops, &k);

    k = 1;
    ruop = bpf_map_lookup_elem(&fsm_ct_ops, &k);

    if (cuop == NULL || ruop == NULL || tdat->ep.nv6) {
        return 0;
    }

    CP_CT_NAT_TACTS(cuop, caop);
    CP_CT_NAT_TACTS(ruop, raop);

    switch (pkt->l34.proto) {
    case IPPROTO_UDP:
        if (pkt->l2.ssnid) {
            if (pkt->ctx.dir == CT_DIR_IN) {
                ckey->sport = pkt->l2.ssnid;
                ckey->dport = pkt->l2.ssnid;
                bpf_map_update_elem(&fsm_ct, ckey, cuop, BPF_ANY);
            } else {
                rkey->sport = pkt->l2.ssnid;
                rkey->dport = pkt->l2.ssnid;
                bpf_map_update_elem(&fsm_ct, rkey, ruop, BPF_ANY);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

INTERNAL(int)
dp_ct_del(xpkt_t *pkt, ct_key_t *ckey, ct_key_t *rkey, ct_op_t *caop,
          ct_op_t *raop)
{
    return 0;
}

INTERNAL(int) dp_ct_in(skb_t *skb, xpkt_t *pkt)
{
    ct_key_t ckey, rkey;
    ct_op_t *cuop, *ruop;
    ct_op_t *caop, *raop;
    nat_endpoint_t *cep, *rep;
    int cidx = 0, ridx = 1;
    int smr = CT_SMR_ERR;

    if (F4_DEBUG_PKT(pkt)) {
        FSM_DBG("[DBG] dp_ct_in\n");
    }

    cuop = bpf_map_lookup_elem(&fsm_ct_ops, &cidx);
    ruop = bpf_map_lookup_elem(&fsm_ct_ops, &ridx);

    if (cuop == NULL || ruop == NULL) {
        return smr;
    }

    cep = &cuop->attr.ep;
    rep = &ruop->attr.ep;

    /* CT Key */
    XADDR_COPY(ckey.daddr, pkt->l34.daddr);
    XADDR_COPY(ckey.saddr, pkt->l34.saddr);
    ckey.sport = pkt->l34.sport;
    ckey.dport = pkt->l34.dport;
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

    caop = bpf_map_lookup_elem(&fsm_ct, &ckey);
    raop = bpf_map_lookup_elem(&fsm_ct, &rkey);
    if (caop == NULL || raop == NULL) {
        FSM_DBG("[CTRK] AAAAA 1\n");
        memset(&cuop->attr.sm, 0, sizeof(ct_sm_t));
        if (cep->nat_flags) {
            cuop->act_type = cep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                                 ? NF_DO_DNAT
                                 : NF_DO_SNAT;
            XADDR_COPY(cuop->nat_act.xip, cep->nat_xip);
            XADDR_COPY(cuop->nat_act.rip, cep->nat_rip);
            // XMAC_COPY(cuop->nat_act.xmac,  cep->nat_xmac);
            // XMAC_COPY(cuop->nat_act.rmac, cep->nat_rmac);
            // cuop->nat_act.xifi = cep->nat_xifi;
            cuop->nat_act.xport = cep->nat_xport;
            cuop->nat_act.rport = cep->nat_rport;
            cuop->nat_act.doct = 0;
            cuop->nat_act.aid = pkt->nat.ep_sel;
            cuop->nat_act.nv6 = pkt->nat.nv6 ? 1 : 0;
            cuop->ito = pkt->nat.ito;
        } else {
            cuop->ito = 0;
            cuop->act_type = NF_DO_CTTK;
        }
        cuop->attr.dir = CT_DIR_IN;

        /* FIXME This is duplicated data */
        cuop->attr.ep_sel = pkt->nat.ep_sel;
        cuop->attr.smr = CT_SMR_INIT;

        memset(&ruop->attr.sm, 0, sizeof(ct_sm_t));
        if (rep->nat_flags) {
            ruop->act_type = rep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                                 ? NF_DO_DNAT
                                 : NF_DO_SNAT;
            XADDR_COPY(ruop->nat_act.xip, rep->nat_xip);
            XADDR_COPY(ruop->nat_act.rip, rep->nat_rip);
            // XMAC_COPY(ruop->nat_act.xmac, rep->nat_xmac);
            // XMAC_COPY(ruop->nat_act.rmac, rep->nat_rmac);
            // ruop->nat_act.xifi = rep->nat_xifi;
            ruop->nat_act.xport = rep->nat_xport;
            ruop->nat_act.rport = rep->nat_rport;
            ruop->nat_act.doct = 0;
            ruop->nat_act.aid = pkt->nat.ep_sel;
            ruop->nat_act.nv6 = ckey.v6 ? 1 : 0;
            ruop->ito = pkt->nat.ito;
        } else {
            ruop->ito = 0;
            ruop->act_type = NF_DO_CTTK;
        }
        ruop->lts = cuop->lts;
        ruop->attr.dir = CT_DIR_OUT;
        ruop->attr.smr = CT_SMR_INIT;
        ruop->attr.ep_sel = cuop->attr.ep_sel;

        bpf_map_update_elem(&fsm_ct, &rkey, ruop, BPF_ANY);
        bpf_map_update_elem(&fsm_ct, &ckey, cuop, BPF_ANY);

        caop = bpf_map_lookup_elem(&fsm_ct, &ckey);
        raop = bpf_map_lookup_elem(&fsm_ct, &rkey);
    }

    if (caop != NULL && raop != NULL) {
        FSM_DBG("[CTRK] AAAAA 2\n");
        caop->lts = bpf_ktime_get_ns();
        raop->lts = caop->lts;
        pkt->ctx.act = F4_PIPE_RDR;
        if (caop->attr.dir == CT_DIR_IN) {
            pkt->ctx.dir = CT_DIR_IN;
            pkt->ctx.phit |= F4_DP_CTSI_HIT;
            smr = dp_ct_sm(skb, pkt, caop, raop, CT_DIR_IN);
        } else {
            pkt->ctx.dir = CT_DIR_OUT;
            pkt->ctx.phit |= F4_DP_CTSO_HIT;
            smr = dp_ct_sm(skb, pkt, raop, caop, CT_DIR_OUT);
        }

        if (smr == CT_SMR_EST) {
            if (cep->nat_flags) {
                caop->nat_act.doct = 0;
                raop->nat_act.doct = 0;
                if (caop->attr.dir == CT_DIR_IN) {
                    dp_ct_est(pkt, &ckey, &rkey, caop, raop);
                } else {
                    dp_ct_est(pkt, &rkey, &ckey, raop, caop);
                }
            } else {
                caop->act_type = NF_DO_NOOP;
                raop->act_type = NF_DO_NOOP;
            }
        } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
            bpf_map_delete_elem(&fsm_ct, &rkey);
            bpf_map_delete_elem(&fsm_ct, &ckey);

            if (F4_DEBUG_PKT(pkt)) {
                FSM_DBG("[DBG] [CTRK] bpf_map_delete_elem by igr\n");
            }

            if (caop->attr.dir == CT_DIR_IN) {
                dp_ct_del(pkt, &ckey, &rkey, caop, raop);
            } else {
                dp_ct_del(pkt, &rkey, &ckey, raop, caop);
            }
        }
    }

    return smr;
}

#endif