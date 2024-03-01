/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP router.
 *
 * Version:	@(#)route.h	1.0.4	05/27/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Fixes:
 *		Alan Cox	:	Reformatted. Added ip_rt_local()
 *		Alan Cox	:	Support for TCP parameters.
 *		Alexey Kuznetsov:	Major changes for new routing code.
 *		Mike McLagan    :	Routing by source
 *		Robert Olsson   :	Added rt_cache statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _ROUTE_H
#define _ROUTE_H

#include <net/dst.h>
#include <net/inetpeer.h>
#include <net/flow.h>
#include <net/sock.h>
#include <linux/in_route.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ip.h>
#include <linux/cache.h>
#include <linux/security.h>

#ifndef __KERNEL__
#warning This file is not supposed to be used outside of kernel.
#endif

#define RTO_ONLINK	0x01

#define RTO_CONN	0
/* RTO_CONN is not used (being alias for 0), but preserved not to break
 * some modules referring to it. */

#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))

struct fib_nh;
struct inet_peer;
/*
不要将路由函数表结构 fib_table 与 rtable 混为一谈,fib table内部几乎全是函数指针,它提供了查询或者创建路由的方法;
rtable 则装载着具体路由内容，这些内容都是通过 fib table 的函数查找并初始化到 rtable中的。
*/
struct rtable
{
	union
	{
		struct dst_entry	dst;// 这是目的路由项
	} u;

	/* Cache lookup keys路由缓存查找相关的匹配条件，该结构体中存放了路由缓存匹配的所有参数 */
	struct flowi		fl;// 注意在cache中的查找主要是通过路由键值和下面的信息

	struct in_device	*idev;// 设备
	
	int			rt_genid;//路由ID
	/*相应的取值有RTCF_NOTIFY、RTCF_LOCAL、RTCF_BROADCAST、RTCF_MULTICAST、RTCF_REDIRECTED等*/
	unsigned		rt_flags;
	/*路由项的类型，相应的取值有RTN_UNSPEC、RTN_UNICAST、RTN_LOCAL、RTN_BROADCAST、RTN_MULTICAST等*/
	__u16			rt_type;

	__be32			rt_dst;	/* Path destination 目的地址	*/
	__be32			rt_src;	/* Path source源地址		*/
	int			rt_iif; //入端口


	/* Info on neighbour */
	__be32			rt_gateway; //目的地址或者下一跳网关地址

	/* Miscellaneous cached information */
	__be32			rt_spec_dst; /* RFC1122 specific destination 首选源地址选择*/
	struct inet_peer	*peer; /* long-living peer info 存储ip peer相关的信息*/
};

struct ip_rt_acct
{
	__u32 	o_bytes;//发出的字节数
	__u32 	o_packets; //发出的包数
	__u32 	i_bytes; //接收的字节数
	__u32 	i_packets; //接收的包数
};

struct rt_cache_stat 
{
        unsigned int in_hit;
        unsigned int in_slow_tot;
        unsigned int in_slow_mc;
        unsigned int in_no_route;
        unsigned int in_brd;
        unsigned int in_martian_dst;
        unsigned int in_martian_src;
        unsigned int out_hit;
        unsigned int out_slow_tot;
        unsigned int out_slow_mc;
        unsigned int gc_total;
        unsigned int gc_ignored;
        unsigned int gc_goal_miss;
        unsigned int gc_dst_overflow;
        unsigned int in_hlist_search;
        unsigned int out_hlist_search;
};

extern struct ip_rt_acct *ip_rt_acct;

struct in_device;
extern int		ip_rt_init(void);
extern void		ip_rt_redirect(__be32 old_gw, __be32 dst, __be32 new_gw,
				       __be32 src, struct net_device *dev);
extern void		rt_cache_flush(int how);
extern int		__ip_route_output_key(struct net *, struct rtable **, const struct flowi *flp);
extern int		ip_route_output_key(struct net *, struct rtable **, struct flowi *flp);
extern int		ip_route_output_flow(struct net *, struct rtable **rp, struct flowi *flp, struct sock *sk, int flags);
extern int		ip_route_input(struct sk_buff*, __be32 dst, __be32 src, u8 tos, struct net_device *devin);
extern unsigned short	ip_rt_frag_needed(struct net *net, struct iphdr *iph, unsigned short new_mtu, struct net_device *dev);
extern void		ip_rt_send_redirect(struct sk_buff *skb);

extern unsigned		inet_addr_type(struct net *net, __be32 addr);
extern unsigned		inet_dev_addr_type(struct net *net, const struct net_device *dev, __be32 addr);
extern void		ip_rt_multicast_event(struct in_device *);
extern int		ip_rt_ioctl(struct net *, unsigned int cmd, void __user *arg);
extern void		ip_rt_get_source(u8 *src, struct rtable *rt);
extern int		ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb);

struct in_ifaddr;
extern void fib_add_ifaddr(struct in_ifaddr *);

static inline void ip_rt_put(struct rtable * rt)
{
	if (rt)
		dst_release(&rt->u.dst);
}

#define IPTOS_RT_MASK	(IPTOS_TOS_MASK & ~3)

extern const __u8 ip_tos2prio[16];

static inline char rt_tos2priority(u8 tos)
{
	return ip_tos2prio[IPTOS_TOS(tos)>>1];
}

static inline int ip_route_connect(struct rtable **rp, __be32 dst,
				   __be32 src, u32 tos, int oif, u8 protocol,
				   __be16 sport, __be16 dport, struct sock *sk,
				   int flags)
{
	//初始化查询路由键值
	struct flowi fl = { .oif = oif,//出接口索引
			    .mark = sk->sk_mark, //设置的mark值
			    .nl_u = { .ip4_u = { .daddr = dst,//目标地址
						 .saddr = src,//源地址
						 .tos   = tos } }, //tos
			    .proto = protocol, //协议号
			    .uli_u = { .ports =
				       { .sport = sport, //源端口
					 .dport = dport } } }; //目标端口

	int err;
	struct net *net = sock_net(sk);
	if (!dst || !src) {//如果没有指定源地址或者目的地址，则要查询路由表
		err = __ip_route_output_key(net, rp, &fl);
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;//使用路由的目标地址
		fl.fl4_src = (*rp)->rt_src; //使用路由的源地址
		ip_rt_put(*rp);//递减路由项计数器
		*rp = NULL;
	}
	security_sk_classify_flow(sk, &fl);
	return ip_route_output_flow(net, rp, &fl, sk, flags);//再次查找并调整地址
}

static inline int ip_route_newports(struct rtable **rp, u8 protocol,
				    __be16 sport, __be16 dport, struct sock *sk)
{
	if (sport != (*rp)->fl.fl_ip_sport ||
	    dport != (*rp)->fl.fl_ip_dport) {//源端口或者目标端口于路由表中不同，也就是发送了变化
		struct flowi fl;

		memcpy(&fl, &(*rp)->fl, sizeof(fl));//复制路由表的键值内容
		fl.fl_ip_sport = sport;//修改为设置的源端口
		fl.fl_ip_dport = dport;//修改为设置的目标端口
		fl.proto = protocol;//使用IP协议
		ip_rt_put(*rp);//放弃对原路由表的使用
		*rp = NULL;
		security_sk_classify_flow(sk, &fl);
		return ip_route_output_flow(sock_net(sk), rp, &fl, sk, 0);//创建路由表
	}
	return 0;
}

extern void rt_bind_peer(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	rt_bind_peer(rt, 0);
	return rt->peer;
}

extern ctl_table ipv4_route_table[];

#endif	/* _ROUTE_H */
