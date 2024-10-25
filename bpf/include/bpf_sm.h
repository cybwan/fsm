#ifndef __F4_BPF_SM_H__
#define __F4_BPF_SM_H__

#include "bpf_macros.h"
#include "bpf_dbg.h"
#include "bpf_dp.h"
#include "bpf_mdi.h"

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

#endif