#ifndef __F4_BPF_DP_H__
#define __F4_BPF_DP_H__

enum {
    NF_DO_DROP = 0,
    NF_DO_SNAT = 1,
    NF_DO_DNAT = 2,
    NF_DO_RDRT = 3,
    NF_DO_CTTK = 4,
    NF_DO_NOOP = 5
};

/* Connection tracking related defines */
typedef enum { CT_DIR_IN = 0, CT_DIR_OUT, CT_DIR_MAX } ct_dir_t;

typedef enum {
    CT_STATE_NONE = 0x0,
    CT_STATE_REQ = 0x1,
    CT_STATE_REP = 0x2,
    CT_STATE_EST = 0x4,
    CT_STATE_FIN = 0x8,
    CT_STATE_DOR = 0x10
} ct_state_t;

typedef enum {
    CT_SMR_ERR = -1,
    CT_SMR_INPROG = 0,
    CT_SMR_EST = 1,
    CT_SMR_UEST = 2,
    CT_SMR_FIN = 3,
    CT_SMR_CTD = 4,
    CT_SMR_UNT = 100,
    CT_SMR_INIT = 200,
} ct_smr_t;

#define CT_TCP_FIN_MASK                                                        \
    (CT_TCP_FINI | CT_TCP_FINI2 | CT_TCP_FINI3 | CT_TCP_CLOSE_WAIT)
#define CT_TCP_SYNC_MASK (CT_TCP_SYN_SEND | CT_TCP_SYN_ACK)

typedef enum {
    CT_TCP_CLOSED = 0x0,
    CT_TCP_SYN_SEND = 0x1,
    CT_TCP_SYN_ACK = 0x2,
    CT_TCP_ESTABLISHED = 0x4,
    CT_TCP_FINI = 0x10,
    CT_TCP_FINI2 = 0x20,
    CT_TCP_FINI3 = 0x40,
    CT_TCP_CLOSE_WAIT = 0x80,
    CT_TCP_ERR = 0x100
} ct_tcp_state_t;

typedef struct {
    __u16 hstate;
#define CT_TCP_INIT_ACK_THRESHOLD 3
    __u16 init_acks;
    __u32 seq;
    __be32 pack;
    __be32 pseq;
} ct_tcp_sm_dir_t;

typedef struct {
    ct_tcp_state_t state;
    ct_dir_t fndir;
    ct_tcp_sm_dir_t dirs[CT_DIR_MAX];
} ct_tcp_sm_t;

#define CT_UDP_FIN_MASK (CT_UDP_FINI)

typedef enum {
    CT_UDP_CNI = 0x0,
    CT_UDP_UEST = 0x1,
    CT_UDP_EST = 0x2,
    CT_UDP_FINI = 0x8,
    CT_UDP_CW = 0x10,
} ct_udp_state_t;

typedef struct {
    __u16 state;
#define CT_UDP_CONN_THRESHOLD 4
    __u16 pkts_seen;
    __u16 rpkts_seen;
    ct_dir_t fndir;
} ct_udp_sm_t;

typedef enum {
    CT_ICMP_CLOSED = 0x0,
    CT_ICMP_REQS = 0x1,
    CT_ICMP_REPS = 0x2,
    CT_ICMP_FINI = 0x4,
    CT_ICMP_DUNR = 0x8,
    CT_ICMP_TTL = 0x10,
    CT_ICMP_RDR = 0x20,
    CT_ICMP_UNK = 0x40,
} ct_icmp_state_t;

typedef struct {
    __u8 state;
    __u8 errs;
    __u16 lseq;
} ct_icmp_sm_t;

typedef struct {
    union {
        ct_tcp_sm_t t;
        ct_udp_sm_t u;
        ct_icmp_sm_t i;
    };
} ct_sm_t;

struct dp_rdr_act {
    __u16 oport;
    __u16 fin;
};

#define nat_xip4 nat_xip[0]
#define nat_rip4 nat_rip[0]

typedef struct {
    __u8 nat_flags;
    __u8 nv6;
    __u16 nat_xifi;
    __u16 nat_xport;
    __u16 nat_rport;
    __u32 nat_xip[4];
    __u32 nat_rip[4];
    __u8 nat_xmac[6];
    __u8 nat_rmac[6];
    __u8 inactive;
} __attribute__((packed)) nat_endpoint_t;

struct xpkt_fib4_key {
    __u32 daddr;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
    __u16 ifi;
    __u8 proto;
} __attribute__((packed));
typedef struct xpkt_fib4_key fib4_key_t;

struct dp_nat_act {
    __u32 xip[4];
    __u32 rip[4];
    __u16 xport;
    __u16 rport;
    __u16 xifi;
    __u8 xmac[6];
    __u8 rmac[6];
    __u8 fin;
    __u8 doct;
    __u32 rid;
    __u32 aid;
    __u8 nv6;
    __u8 nmh;
};

struct xpkt_fib4_op {
    __u8 act_type; /* Possible actions : See below */
    union {
        struct dp_rdr_act port_act;
        struct dp_nat_act nat_act; /* NF_DO_SNAT, NF_DO_DNAT */
    };
};

struct xpkt_fib4_ops {
    __u8 act_type;
    __u64 its;
    struct xpkt_fib4_op ops[F4_FCV4_MAP_ACTS];
};
typedef struct xpkt_fib4_ops fib4_ops_t;

typedef struct {
    __u32 daddr[4];
    __u16 dport;
    __u8 proto;
    __u8 v6;
} __attribute__((packed)) nat_key_t;

#define NAT_LB_ALGO_RDRB 0
#define NAT_LB_ALGO_HASH 1

typedef struct {
    __u64 ito;
    __u64 pto;
    struct bpf_spin_lock lock;
    __u8 nat_type;
    __u8 lb_algo;
    __u8 ep_sel;
    __u8 ep_cnt;
    nat_endpoint_t endpoints[F4_MAX_ENDPOINTS];
} nat_ops_t;

typedef struct {
    __u32 daddr[4];
    __u32 saddr[4];
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 v6;
} __attribute__((packed)) ct_key_t;

typedef struct {
    __u16 rid;
    __u16 aid;
    __u32 nid;
    ct_dir_t dir;
    ct_sm_t sm;
    ct_smr_t smr;
    nat_endpoint_t ep;
} ct_attr_t;

typedef struct {
    __u8 act_type; /* Possible actions :
                    *  NF_DO_DROP
                    *  DP_SET_TOCP
                    *  NF_DO_NOOP
                    *  NF_DO_RDRT
                    *  DP_SET_RT_NHNUM
                    *  DP_SET_SESS_FWD_ACT
                    */
    struct bpf_spin_lock lock;
    ct_attr_t attr;
    __u64 ito; /* Inactive timeout */
    __u64 lts; /* Last used timestamp */
    union {
        struct dp_rdr_act port_act;
        struct dp_nat_act nat_act;
    };
} ct_op_t;

struct dp_dnat_opt_key {
    __u32 xaddr;
    __u16 xport;
    __u8 proto;
    __u8 v6;
};

struct dp_dnat_opt_tact {
    __u32 daddr;
    __u32 saddr;
    __u16 dport;
    __u16 sport;
    __u64 ts;
};

struct dp_snat_opt_key {
    __u32 daddr;
    __u32 saddr;
    __u16 dport;
    __u16 sport;
    __u8 proto;
    __u8 v6;
};

struct dp_snat_opt_tact {
    __u32 xaddr;
    __u16 xport;
};

struct dp_t4 {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
} __attribute__((aligned(4)));

struct dp_t2_addr {
    __be32 saddr;
    __be32 daddr;
} __attribute__((aligned(4)));

struct dp_t2_port {
    __be16 sport;
    __be16 dport;
} __attribute__((aligned(4)));

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif

#define XPKT_PTR(x) ((void *)((long)x))
#define XPKT_PTR_ADD(x, len) ((void *)(((__u8 *)((long)x)) + (len)))
#define XPKT_PTR_SUB(x, y) (((__u8 *)XPKT_PTR(x)) - ((__u8 *)XPKT_PTR(y)))

#define XADDR_IS_ZERO(var)                                                     \
    ((var)[0] == 0 && (var)[1] == 0 && (var)[2] == 0 && (var)[3] == 0)

#define XADDR_COPY(dst, src)                                                   \
    do {                                                                       \
        (dst)[0] = (src)[0];                                                   \
        (dst)[1] = (src)[1];                                                   \
        (dst)[2] = (src)[2];                                                   \
        (dst)[3] = (src)[3];                                                   \
    } while (0)

#define XADDR_SET_ZERO(var)                                                    \
    do {                                                                       \
        (var)[0] = 0;                                                          \
        (var)[1] = 0;                                                          \
        (var)[2] = 0;                                                          \
        (var)[3] = 0;                                                          \
    } while (0)

#define XMAC_COPY(dst, src)                                                    \
    do {                                                                       \
        (dst)[0] = (src)[0];                                                   \
        (dst)[1] = (src)[1];                                                   \
        (dst)[2] = (src)[2];                                                   \
        (dst)[3] = (src)[3];                                                   \
        (dst)[4] = (src)[4];                                                   \
        (dst)[5] = (src)[5];                                                   \
    } while (0)

#define XMAC_SET_ZERO(var)                                                     \
    do {                                                                       \
        (var)[0] = 0;                                                          \
        (var)[1] = 0;                                                          \
        (var)[2] = 0;                                                          \
        (var)[3] = 0;                                                          \
        (var)[4] = 0;                                                          \
        (var)[5] = 0;                                                          \
    } while (0)

#endif