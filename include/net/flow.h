/*
 *
 *	Generic internet FLOW.
 *
 */

#ifndef _NET_FLOW_H
#define _NET_FLOW_H

#include <linux/in6.h>
#include <asm/atomic.h>

struct flowi {//路由查找相关的数据结构
	int	oif;/*出口设备*/
	int	iif;/*入口设备*/
	__u32	mark;/*mark值*/
	/*三层相关的成员，对于ipv4有目的ip地址、源ip地址、tos、scope等*/
	union {
		struct {
			__be32			daddr; //目标地址
			__be32			saddr; //源地址
			__u8			tos;
			__u8			scope; 
		} ip4_u;
		
		struct {
			struct in6_addr		daddr;
			struct in6_addr		saddr;
			__be32			flowlabel;
		} ip6_u;

		struct {
			__le16			daddr;
			__le16			saddr;
			__u8			scope;
		} dn_u;
	} nl_u;
#define fld_dst		nl_u.dn_u.daddr 
#define fld_src		nl_u.dn_u.saddr 
#define fld_scope	nl_u.dn_u.scope 
#define fl6_dst		nl_u.ip6_u.daddr
#define fl6_src		nl_u.ip6_u.saddr
#define fl6_flowlabel	nl_u.ip6_u.flowlabel
#define fl4_dst		nl_u.ip4_u.daddr//IPv4目标地址
#define fl4_src		nl_u.ip4_u.saddr//IPv4源地址
#define fl4_tos		nl_u.ip4_u.tos
#define fl4_scope	nl_u.ip4_u.scope
	/*四层协议类型与四层协议相关的成员(源、目的端口)等*/
	__u8	proto;
	__u8	flags;
	union {
		struct {
			__be16	sport;
			__be16	dport;
		} ports;

		struct {
			__u8	type;
			__u8	code;
		} icmpt;

		struct {
			__le16	sport;
			__le16	dport;
		} dnports;

		__be32		spi;

		struct {
			__u8	type;
		} mht;
	} uli_u;
#define fl_ip_sport	uli_u.ports.sport
#define fl_ip_dport	uli_u.ports.dport
#define fl_icmp_type	uli_u.icmpt.type
#define fl_icmp_code	uli_u.icmpt.code
#define fl_ipsec_spi	uli_u.spi
#define fl_mh_type	uli_u.mht.type
	__u32           secid;	/* used by xfrm; see secid.txt */
} __attribute__((__aligned__(BITS_PER_LONG/8)));

#define FLOW_DIR_IN	0
#define FLOW_DIR_OUT	1
#define FLOW_DIR_FWD	2

struct sock;
typedef int (*flow_resolve_t)(struct flowi *key, u16 family, u8 dir,
			       void **objp, atomic_t **obj_refp);

extern void *flow_cache_lookup(struct flowi *key, u16 family, u8 dir,
	 		       flow_resolve_t resolver);
extern void flow_cache_flush(void);
extern atomic_t flow_cache_genid;

static inline int flow_cache_uli_match(struct flowi *fl1, struct flowi *fl2)
{
	return (fl1->proto == fl2->proto &&
		!memcmp(&fl1->uli_u, &fl2->uli_u, sizeof(fl1->uli_u)));
}

#endif
