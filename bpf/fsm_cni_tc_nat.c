#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <stddef.h>

__section("classifier_ingress") int fsm_cni_tc_dnat(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    switch (bpf_htons(eth->h_proto)) {
    case ETH_P_IP:
      debugf("fsm_cni_tc_nat [ingress]");
      break;
    default:
      return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

__section("classifier_egress") int fsm_cni_tc_snat(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_SHOT;
    }

    switch (bpf_htons(eth->h_proto)) {
    case ETH_P_IP:
      debugf("fsm_cni_tc_nat [egress]");
    default:
      return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
