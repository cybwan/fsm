#ifndef __F4_BPF_FC_H__
#define __F4_BPF_FC_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"

INTERNAL(int)
xpkt_fib4_init_key(xpkt_t *pkt, struct xpkt_fib4_key *key)
{
    key->daddr = pkt->l34.daddr4;
    key->saddr = pkt->l34.saddr4;
    key->sport = pkt->l34.sport;
    key->dport = pkt->l34.dport;
    key->proto = pkt->l34.proto;
    key->ifi = 0;
    return 0;
}

INTERNAL(int)
xpkt_fib4_find(skb_t *skb, xpkt_t *pkt)
{
    struct xpkt_fib4_key key;
    struct xpkt_fib4_ops *acts;
    struct xpkt_fib4_op *ta;
    int ret = 1;
    int z = 0;

    xpkt_fib4_init_key(pkt, &key);

    acts = bpf_map_lookup_elem(&fsm_fib4, &key);
    if (!acts) {
        /* xfck - fcache key table is maintained so that
         * there is no need to make fcv4 key again in
         * tail-call sections
         */
        bpf_map_update_elem(&fsm_fib4_key, &z, &key, BPF_ANY);
        return 0;
    }

    /* Check timeout */
    if (bpf_ktime_get_ns() - acts->its > FC_V4_DPTO) {
        bpf_map_update_elem(&fsm_fib4_key, &z, &key, BPF_ANY);
        bpf_map_delete_elem(&fsm_fib4, &key);
        pkt->ctx.rcode |= F4_PIPE_RC_FCTO;
        return 0;
    }

    pkt->ctx.phit |= F4_DP_FC_HIT;

    if (acts->ops[NF_DO_SNAT].act_type == NF_DO_SNAT) {
        ta = &acts->ops[NF_DO_SNAT];

        if (ta->act.nat_act.fin == 1 || ta->act.nat_act.doct) {
            pkt->ctx.rcode |= F4_PIPE_RC_FCBP;
            return 0;
        }

        xpkt_nat_load(skb, pkt, &ta->act.nat_act, 1);
    } else if (acts->ops[NF_DO_DNAT].act_type == NF_DO_DNAT) {
        ta = &acts->ops[NF_DO_DNAT];

        if (ta->act.nat_act.fin == 1 || ta->act.nat_act.doct) {
            pkt->ctx.rcode |= F4_PIPE_RC_FCBP;
            return 0;
        }

        xpkt_nat_load(skb, pkt, &ta->act.nat_act, 0);
    }

    /* Catch any conditions which need us to go to cp/ct */
    if (pkt->ctx.l4fin) {
        goto del_out;
    }

    // DP_RUN_CT_HELPER(pkt);

    XMAC_COPY(pkt->l2.dl_src, pkt->nat.nxmac);
    XMAC_COPY(pkt->l2.dl_dst, pkt->nat.nrmac);
    pkt->ctx.oport = pkt->nat.nxifi;

    xpkt_encode_packet_always(skb, pkt);
    // xpkt_encode_packet(skb, pkt);

    F4_PPLN_RDR(pkt);

    return ret;

del_out:
    bpf_map_delete_elem(&fsm_fib4, &key);
    pkt->ctx.rcode |= F4_PIPE_RC_FCBP;
    return 0;
}

INTERNAL(int)
dp_ing_fc_main(skb_t *skb, xpkt_t *pkt)
{
    int z = 0;
    int oif;
    if (pkt->ctx.act == 0 && pkt->l2.dl_type == ntohs(ETH_P_IP)) {
        if (xpkt_fib4_find(skb, pkt) == 1) {
            if (pkt->ctx.act == F4_PIPE_RDR) {
                // oif = pkt->ctx.oport;
                // return bpf_redirect(oif, 0);
                return TC_ACT_OK;
            }
        }
    }

    bpf_map_update_elem(&fsm_xpkts, &z, pkt, BPF_ANY);
    bpf_tail_call(skb, &fsm_progs, FSM_CNI_HANDSHAKE_PROG_ID);
    return TC_ACT_SHOT;
}

INTERNAL(int)
dp_egr_main(skb_t *skb, xpkt_t *pkt)
{
    if (pkt->l2.dl_type == ntohs(ETH_P_IP) &&
        (pkt->l34.proto == IPPROTO_TCP || pkt->l34.proto == IPPROTO_UDP)) {
        struct dp_snat_opt_key key;
        struct dp_snat_opt_tact *adat = NULL;

        memset(&key, 0, sizeof(key));
        key.v6 = 0;
        key.proto = pkt->l34.proto;
        key.saddr = pkt->l34.saddr4;
        key.daddr = pkt->l34.daddr4;
        key.sport = ntohs(pkt->l34.sport);
        key.dport = ntohs(pkt->l34.dport);

        adat = bpf_map_lookup_elem(&fsm_snat_opt, &key);

        if (adat != NULL) {
            if (pkt->ctx.igr) {
                if (pkt->l34.proto == IPPROTO_TCP) {
                    xpkt_csum_replace_tcp_dst_ip(skb, pkt, adat->xaddr);
                    xpkt_csum_replace_tcp_dst_port(skb, pkt,
                                                   htons(adat->xport));
                } else if (pkt->l34.proto == IPPROTO_UDP) {
                    xpkt_csum_replace_udp_dst_ip(skb, pkt, adat->xaddr);
                    xpkt_csum_replace_udp_dst_port(skb, pkt,
                                                   htons(adat->xport));
                }
            } else if (pkt->ctx.egr) {
                if (pkt->l34.proto == IPPROTO_TCP) {
                    xpkt_csum_replace_tcp_src_ip(skb, pkt, adat->xaddr);
                    xpkt_csum_replace_tcp_src_port(skb, pkt,
                                                   htons(adat->xport));
                } else if (pkt->l34.proto == IPPROTO_UDP) {
                    xpkt_csum_replace_udp_src_ip(skb, pkt, adat->xaddr);
                    xpkt_csum_replace_udp_src_port(skb, pkt,
                                                   htons(adat->xport));
                }
            }
        }
    }

    return TC_ACT_OK;
}

#endif