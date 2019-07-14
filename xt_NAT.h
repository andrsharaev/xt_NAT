#ifndef _LINUX_NETFILTER_XT_NAT_H
#define _LINUX_NETFILTER_XT_NAT_H 1

enum xt_nat_target_variant {
    XTNAT_SNAT,
    XTNAT_DNAT,
};

struct xt_nat_tginfo {
    uint8_t variant;
};

#define NETFLOW5_RECORDS_MAX 30

struct netflow5_record {
    __be32		s_addr;
    __be32		d_addr;
    __be32		nexthop;
    __be16		i_ifc;
    __be16		o_ifc;
    __be32		nr_packets;
    __be32		nr_octets;
    __be32		first_ms;
    __be32		last_ms;
    __be16		s_port;
    __be16		d_port;
    __u8		reserved;
    __u8		tcp_flags;
    __u8		protocol;
    __u8		tos;
    __be16		s_as;
    __be16		d_as;
    __u8		s_mask;
    __u8		d_mask;
    __u16		padding;
} __attribute__ ((packed));

/* NetFlow v5 packet */
struct netflow5_pdu {
    __be16			version;
    __be16			nr_records;
    __be32			ts_uptime; /* ms */
    __be32			ts_usecs;  /* s  */
    __be32			ts_unsecs; /* ns */
    __be32			seq;
    __u8			eng_type;
    __u8			eng_id;
    __u16			sampling;
    struct netflow5_record	flow[NETFLOW5_RECORDS_MAX];
} __attribute__ ((packed));

#define NETFLOW5_HEADER_SIZE (sizeof(struct netflow5_pdu) - NETFLOW5_RECORDS_MAX * sizeof(struct netflow5_record))

#endif /* _LINUX_NETFILTER_XT_NAT_H */

