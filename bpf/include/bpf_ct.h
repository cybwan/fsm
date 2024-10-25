#ifndef __F4_BPF_CT_H__
#define __F4_BPF_CT_H__

#include "bpf_macros.h"
#include "bpf_dbg.h"
#include "bpf_dp.h"
#include "bpf_mdi.h"
#include "bpf_sm.h"

#define dp_run_ctact_helper(x, a)                                              \
    do {                                                                       \
        switch ((a)->nf) {                                                     \
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

#define CP_CT_NAT_TACTS(dst, src)                                              \
    memcpy(&dst->attr, &src->attr, sizeof(ct_attr_t));                         \
    dst->ito = src->ito;                                                       \
    dst->lts = src->lts;                                                       \
    memcpy(&dst->nfs.nat, &src->nfs.nat, sizeof(nf_nat_t));

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
            cuop->nf = cep->nat_flags & (F4_NAT_DST | F4_NAT_HDST) ? NF_DO_DNAT
                                                                   : NF_DO_SNAT;
            XADDR_COPY(cuop->nfs.nat.xip, cep->nat_xip);
            XADDR_COPY(cuop->nfs.nat.rip, cep->nat_rip);
            // XMAC_COPY(cuop->nat_act.xmac,  cep->nat_xmac);
            // XMAC_COPY(cuop->nat_act.rmac, cep->nat_rmac);
            // cuop->nat_act.xifi = cep->nat_xifi;
            cuop->nfs.nat.xport = cep->nat_xport;
            cuop->nfs.nat.rport = cep->nat_rport;
            cuop->nfs.nat.doct = 0;
            cuop->nfs.nat.aid = pkt->nat.ep_sel;
            cuop->nfs.nat.nv6 = pkt->nat.nv6 ? 1 : 0;
            cuop->ito = pkt->nat.ito;
        } else {
            cuop->ito = 0;
            cuop->nf = NF_DO_CTTK;
        }
        cuop->attr.dir = CT_DIR_IN;

        /* FIXME This is duplicated data */
        cuop->attr.ep_sel = pkt->nat.ep_sel;
        cuop->attr.smr = CT_SMR_INIT;

        memset(&ruop->attr.sm, 0, sizeof(ct_sm_t));
        if (rep->nat_flags) {
            ruop->nf = rep->nat_flags & (F4_NAT_DST | F4_NAT_HDST) ? NF_DO_DNAT
                                                                   : NF_DO_SNAT;
            XADDR_COPY(ruop->nfs.nat.xip, rep->nat_xip);
            XADDR_COPY(ruop->nfs.nat.rip, rep->nat_rip);
            // XMAC_COPY(ruop->nat_act.xmac, rep->nat_xmac);
            // XMAC_COPY(ruop->nat_act.rmac, rep->nat_rmac);
            // ruop->nat_act.xifi = rep->nat_xifi;
            ruop->nfs.nat.xport = rep->nat_xport;
            ruop->nfs.nat.rport = rep->nat_rport;
            ruop->nfs.nat.doct = 0;
            ruop->nfs.nat.aid = pkt->nat.ep_sel;
            ruop->nfs.nat.nv6 = ckey.v6 ? 1 : 0;
            ruop->ito = pkt->nat.ito;
        } else {
            ruop->ito = 0;
            ruop->nf = NF_DO_CTTK;
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
                caop->nfs.nat.doct = 0;
                raop->nfs.nat.doct = 0;
                if (caop->attr.dir == CT_DIR_IN) {
                    dp_ct_est(pkt, &ckey, &rkey, caop, raop);
                } else {
                    dp_ct_est(pkt, &rkey, &ckey, raop, caop);
                }
            } else {
                caop->nf = NF_DO_NOOP;
                raop->nf = NF_DO_NOOP;
            }
        } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
            bpf_map_delete_elem(&fsm_ct, &rkey);
            bpf_map_delete_elem(&fsm_ct, &ckey);

            if (F4_DEBUG_PKT(pkt)) {
                FSM_DBG("[DBG] [CTRK] bpf_map_delete_elem by igr\n");
            }
        }
    }

    return smr;
}

#endif