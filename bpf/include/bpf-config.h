#ifndef __F4_BPF_CONFIG_H__ 
#define __F4_BPF_CONFIG_H__

#define MESH_CNI_HANDSHAKE_PROG_ID (1)
#define MESH_CNI_CONNTRACK_PROG_ID (2)
#define MESH_CNI_PASS_PROG_ID      (3)
#define MESH_CNI_DROP_PROG_ID      (4)
#define FSM_PROGS_MAP_ENTRIES      (5)

#define F4_MAX_LB_NODES      (2)
#define F4_MAX_IFI_ADDRS     (4*1024)
#define F4_CT_MAP_ENTRIES    (1024*1024*F4_MAX_LB_NODES)
#define F4_NATV4_MAP_ENTRIES (4*1024)
#define F4_NAT_EP_MAP_ENTRIES (4*1024)
#define F4_FCV4_MAP_ENTRIES  (F4_CT_MAP_ENTRIES)
#define F4_MAX_NXFRMS        (16)

#define F4_FCV4_MAP_ACTS     (DP_SET_TOCP+1)


/* Hard-timeout of 40s for fc dp entry */
#define FC_V4_DPTO            (60000000000)

/* Hard-timeout of 2m for fc cp entry */
#define FC_V4_CPTO            (120000000000)

/* Hard-timeout of 30m for ct entry */
#define CT_V4_CPTO            (1800000000000)

/* Hard-timeouts for ct xxx entry */
#define CT_TCP_FN_CPTO        (10000000000)
#define CT_SCTP_FN_CPTO       (20000000000)
#define CT_UDP_FN_CPTO        (10000000000)
#define CT_UDP_EST_CPTO       (20000000000)
#define CT_ICMP_EST_CPTO      (20000000000)
#define CT_ICMP_FN_CPTO       (5000000000)
#define CT_MISMATCH_FN_CPTO   (180000000000)

#endif