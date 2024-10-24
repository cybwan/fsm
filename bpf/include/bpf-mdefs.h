#ifndef __F4_BPF_MDEFS_H__
#define __F4_BPF_MDEFS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = FSM_PROGS_MAP_ENTRIES,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, FSM_PROGS_MAP_ENTRIES);
} fsm_progs SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_xpkts = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct xfrm),
    .max_entries = 1,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xpkt);
    __uint(max_entries, 1);
} fsm_xpkts SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_fib4_key = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct xpkt_fib4_key),
    .max_entries = 1,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xpkt_fib4_key);
    __uint(max_entries, 1);
} fsm_fib4_key SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_fib4_ops = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct xpkt_fib4_ops),
    .max_entries = 1,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct xpkt_fib4_ops);
    __uint(max_entries, 1);
} fsm_fib4_ops SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_fib4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(fib4_key_t),
    .value_size = sizeof(fib4_ops_t),
    .max_entries = F4_FCV4_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, fib4_key_t);
    __type(value, fib4_ops_t);
    __uint(max_entries, F4_FCV4_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_fib4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_nat = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(nat_key_t),
    .value_size = sizeof(nat_ops_t),
    .max_entries = F4_NATV4_MAP_ENTRIES,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, nat_key_t);
    __type(value, nat_ops_t);
    __uint(max_entries, F4_NATV4_MAP_ENTRIES);
} fsm_nat SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_ct_ops = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(ct_op_t),
    .max_entries = 2,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, ct_op_t);
    __uint(max_entries, 2);
} fsm_ct_ops SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_ct = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(ct_key_t),
    .value_size = sizeof(ct_op_t),
    .max_entries = F4_CT_MAP_ENTRIES,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, ct_key_t);
    __type(value, ct_op_t);
    __uint(max_entries, F4_CT_MAP_ENTRIES);
} fsm_ct SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_igr_ipv4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = F4_MAX_IFI_ADDRS,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, F4_MAX_IFI_ADDRS);
} fsm_igr_ipv4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_egr_ipv4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = F4_MAX_IFI_ADDRS,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, F4_MAX_IFI_ADDRS);
} fsm_egr_ipv4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_dnat_opt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct dp_dnat_opt_key),
    .value_size = sizeof(struct dp_dnat_opt_tact),
    .max_entries = F4_FCV4_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dp_dnat_opt_key);
    __type(value, struct dp_dnat_opt_tact);
    __uint(max_entries, F4_FCV4_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_dnat_opt SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") fsm_snat_opt = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct dp_snat_opt_key),
    .value_size = sizeof(struct dp_snat_opt_tact),
    .max_entries = F4_FCV4_MAP_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
#else /* New BTF definitions */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dp_snat_opt_key);
    __type(value, struct dp_snat_opt_tact);
    __uint(max_entries, F4_FCV4_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fsm_snat_opt SEC(".maps");
#endif
#endif