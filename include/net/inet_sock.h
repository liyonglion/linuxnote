/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>
#include <net/route.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {//IP选项结构
	__be32		faddr;//转发地址
	unsigned char	optlen;//选项长度
	unsigned char	srr;//源路由在头部的位置
	unsigned char	rr;//记录路由在头部的位置
	unsigned char	ts;//时间戳在头部的位置
	unsigned char	is_strictroute:1,//标识强制路由
			srr_is_hit:1,//表示数据包目的地址在源路由中
			is_changed:1,//表示IP检验和需要重新计算
			rr_needaddr:1,//需要记录路由地址
			ts_needtime:1,//需要时间
			ts_needaddr:1;//需要输出设备地址
	unsigned char	router_alert;//路由警报
	unsigned char	cipso;//商业互联安全协议选项
	unsigned char	__pad2;//用于数据对齐
	unsigned char	__data[0];//用于保存IP选项数据指针
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
	/* 2 bytes hole, try to pack */
#endif
	__be32			loc_addr;//本地地址
	__be32			rmt_addr;//远程地址
	__be16			rmt_port;//远程端口
	u16			snd_wscale : 4, //客户端的窗口扩大因子
				rcv_wscale : 4, //服务器端的窗口扩大因子
				tstamp_ok  : 1,//表示本连接的连接是否支持时间戳
				sack_ok	   : 1,//标识本链接是否支持SACK选项
				wscale_ok  : 1,//标识本连接是否支持window Scale选项
				ecn_ok	   : 1,//标识本连接是否支持ECN选项
				acked	   : 1;
	struct ip_options	*opt; //IP头选项相关
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @daddr - Foreign IPv4 addr
 * @rcv_saddr - Bound local IPv4 addr
 * @dport - Destination port
 * @num - Local port
 * @saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @sport - Source port
 * @id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {//inet协议族结构。描述ip协议的通用传输控制信息，相比sock增加了套接字地址、端口等信息。
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	__be32			daddr; //目标地址
	__be32			rcv_saddr;//用户配置的监听地址，在inet_bind()中赋值
	__be16			dport;//目标端口
	__u16			num; //绑定端口号，在connect流程中，表示筛选出来的端口号
	__be32			saddr;//源地址。在bind过程中，rcv_saddr = saddr
	__s16			uc_ttl; //单播TTL
	__u16			cmsg_flags;
	struct ip_options	*opt;//IP选项
	__be16			sport;//绑定端口号
	__u16			id;//ip 头中的流ID，用于DF包的标识
	__u8			tos;
	__u8			mc_ttl;//组播TTL
	__u8			pmtudisc;//是否按照MTU分包
	__u8			recverr:1,
				is_icsk:1, //标识是否是inet_connection_sock类型
				freebind:1,
				hdrincl:1,
				mc_loop:1;
	int			mc_index;//组播设备索引
	__be32			mc_addr;//组播地址
	struct ip_mc_socklist	*mc_list;//组播表
	struct {
		unsigned int		flags;
		unsigned int		fragsize;//IP分片大小
		struct ip_options	*opt;//IP选项
		struct dst_entry	*dst;//路由缓存项
		int			length; /* Total length of all frames */
		__be32			addr;
		struct flowi		fl;//路由查找项
	} cork;//这些信息用于每个IP片段建立IP头部时使用
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

extern u32 inet_ehash_secret;
extern void build_ehash_secret(void);

static inline unsigned int inet_ehashfn(const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	return jhash_3words((__force __u32) laddr,
			    (__force __u32) faddr,
			    ((__u32) lport) << 16 | (__force __u32)fport,
			    inet_ehash_secret);
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __be32 faddr = inet->daddr;
	const __be16 fport = inet->dport;

	return inet_ehashfn(laddr, lport, faddr, fport);
}


static inline int inet_iif(const struct sk_buff *skb)
{
	return skb->rtable->rt_iif;
}

static inline struct request_sock *inet_reqsk_alloc(struct request_sock_ops *ops)
{
	struct request_sock *req = reqsk_alloc(ops);

	if (req != NULL)
		inet_rsk(req)->opt = NULL;

	return req;
}

#endif	/* _INET_SOCK_H */
