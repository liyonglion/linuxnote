/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	u8			fc_dst_len;//目标掩码长度
	u8			fc_tos; //TOS
	/*
	proto字段的定义在内核中并没有实质的意义，只是一个显示字段。
	RTPROT_UNSPEC表示未指定；RTPROT_REDIRECT已经不再使用；内核自身添加的路由使用RTPROT_KERNEL；RTPROT_BOOT为在启动过程中安装的路由；
	数值大于RTPROT_STATIC（4）的proto值，不由内核解释。内核只是在路由下发时保存此值，显示时回显此值。
	*/
	u8			fc_protocol; // boot、static、kernel
	/*
		global: 当地址可以在任何地方使用时，它具有全局作用域。这是大多数地址的默认作用域
		link: 表示目的前缀（前缀表示目标 IP 地址，包括网络掩码（如果存在））直连在该接口上。例如：192.168.10.0/24 dev eth0  proto kernel  scope link  src 192.168.10.11 网段192.168.10.0/24直连再eth0网卡上，“src”是分配给离开此服务器并沿此路由（源 NAT）继续前进的数据包的 IPv4 源地址。
		host: 仅在当前主机(服务器)内有效。当地址仅用于在主机本身内部通信时，它具有主机作用域。在主机外部，这个地址是未知的，不能使用。例如，loopback地址为127.0.0.1
	*/
	u8			fc_scope; //global、link 、host
	/*
		broadcast:报文以链路广播消息的形式发送
		blackhole:数据包被静默丢弃
		local:数据包被传送到环回设备(服务器本地)。
		prohibit:数据包被拒绝;返回错误，“通信被管理禁止”。
		throw:路由表查找终止，包丢掉，并返回错误消息-"网络不可达"
		unicast:到目的地址的路径是单播(这是大多数路由)，这个是默认的。
		unreachable:数据包被丢弃，并返回ICMP错误消息“主机不可达”。
	*/
	u8			fc_type; //broadcast、blackhole、local、prohibit、throw、unicast、unreachable
	/* 3 bytes unused */
	u32			fc_table; //路由表ID
	__be32			fc_dst; //目标地址
	__be32			fc_gw; //网关地址
	int			fc_oif;//出接口索引
	u32			fc_flags; //路由信息标志
	u32			fc_priority; //优先级
	__be32			fc_prefsrc; //源地址
	struct nlattr		*fc_mx; //将fc_mx的信息都将解析到fib_info.fib_metrics[RTAX_MAX]中
	struct rtnexthop	*fc_mp; //配置的下一跳数组。例如：ip route add default scope global nexthop dev ppp0 nexthop dev ppp1
	int			fc_mx_len;
	int			fc_mp_len;// 配置的跳转结构的总长度
	u32			fc_flow;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
 };

struct fib_info;
//ip table manual 中定义的NH := [ encap ENCAP ] [ via [ FAMILY ] ADDRESS ] [ dev STRING ] [weight NUMBER ] NHFLAGS
//NHFLAGS := [ onlink | pervasive ]
struct fib_nh {
	struct net_device	*nh_dev; //下一条设备
	struct hlist_node	nh_hash; 
	struct fib_info		*nh_parent;//持有者
	unsigned		nh_flags;//上面注释信息NHFLAGS
	unsigned char		nh_scope; //范围
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			nh_weight; //权重
	int			nh_power; //负载
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	__u32			nh_tclassid;
#endif
	int			nh_oif; //出接口索引
	__be32			nh_gw; //上面注释的via
};

/*
 * This structure contains data shared by many of routes.
 */

struct fib_info {// 具体怎么路由这个数据包的信息
	struct hlist_node	fib_hash;// 链接到fib_info_hash队列
	struct hlist_node	fib_lhash;// 链接到fib_hash_laddrhash队列
	struct net		*fib_net;// 所属网络空间
	int			fib_treeref;// 路由信息结构使用计数器
	atomic_t		fib_clntref;// 释放路由信息结构(fib)计数器
	int			fib_dead;// 标志路由被删除了
	unsigned		fib_flags;// 标识位
	int			fib_protocol;// 安装路由协议
	__be32			fib_prefsrc;// 指定源IP，源地址和目的地址组成一个路由
	u32			fib_priority;// 路由优先级
	u32			fib_metrics[RTAX_MAX];// 保存负载值
#define fib_mtu fib_metrics[RTAX_MTU-1]// MTU值
#define fib_window fib_metrics[RTAX_WINDOW-1]// 窗口值
#define fib_rtt fib_metrics[RTAX_RTT-1]// RTT值
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]// MSS值(对外公开的)
	int			fib_nhs;// 倒数第二个字段即:跳转结构的数组个数
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			fib_power;// 支持多路径时候使用
#endif
	struct fib_nh		fib_nh[0];// 跳转结构(就是该怎么路由)。例如配置：ip route add default scope global nexthop dev ppp0 nexthop dev ppp1。
	//对于上面的fib_nh[0]，这样的操作手法在内核中也是常见的。代表会有这个字段的存在，但是具体是几个并不知道，因为可能是动态的，所以需要一个计数表示，也就是fib_power
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result {
	unsigned char	prefixlen;//掩码长度
	unsigned char	nh_sel;//路由下一条索引，在fib_info.fib_nh数组中
	unsigned char	type; /*路由项的类型:为RTN_MULTICAST、RTN_UNICAST、RTN_BROADCAST等*/
	unsigned char	scope; /*路由项的scope:取值为RT_SCOPE_UNIVERSE、RT_SCOPE_LINK等*/
	struct fib_info *fi; //路由项
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;/*指向关联的fib_rule结构的变量，用于策略路由*/
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#define FIB_TABLE_HASHSZ 2

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#define FIB_TABLE_HASHSZ 256

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

struct fib_table {//路由表是由fib_table表示。而fib_table则给路由表提供了查询路由信息的操作。为了区分，我们称为路由函数表
	struct hlist_node tb_hlist;//hash节点，通过ipv4.hlist_head得到属于自己的路由表FIB
	u32		tb_id;// 标识符(例如：本地路由，主路由，默认路由)
	unsigned	tb_stamp;// 时间戳
	int		tb_default;// 路由信息结构队列序号
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);// 查找函数
	int		(*tb_insert)(struct fib_table *, struct fib_config *);// 添加函数
	int		(*tb_delete)(struct fib_table *, struct fib_config *);// 删除函数
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);// 用于路由转发
	int		(*tb_flush)(struct fib_table *table);
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);// 设置默认路由

	unsigned char	tb_data[0];// 数据区。注意这个特殊字段，标识结构的结尾，分配fib_table同时分配fn_hash结构。也就是fib_table之后就是fn_hash结构
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define TABLE_LOCAL_INDEX	0
#define TABLE_MAIN_INDEX	1

static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];
	return hlist_entry(ptr->first, struct fib_table, tb_hlist);
}
//id: 路由表ID
//net: 网络空间
static inline struct fib_table *fib_new_table(struct net *net, u32 id)
{
	return fib_get_table(net, id);
}
//不支持多路由时，只查询locl和main路由表即可
static inline int fib_lookup(struct net *net, const struct flowi *flp,
			     struct fib_result *res)
{
	struct fib_table *table;

	table = fib_get_table(net, RT_TABLE_LOCAL);
	if (!table->tb_lookup(table, flp, res))
		return 0;

	table = fib_get_table(net, RT_TABLE_MAIN);
	if (!table->tb_lookup(table, flp, res))
		return 0;
	return -ENETUNREACH;
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern int __net_init fib4_rules_init(struct net *net);
extern void __net_exit fib4_rules_exit(struct net *net);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

extern int fib_lookup(struct net *n, struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(struct net *net, u32 id);
extern struct fib_table *fib_get_table(struct net *net, u32 id);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst, u32 *itag);
extern void fib_select_default(struct net *net, const struct flowi *flp,
			       struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down_dev(struct net_device *dev, int force);
extern int fib_sync_down_addr(struct net *net, __be32 local);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

/* Exported by fib_{hash|trie}.c */
extern void fib_hash_init(void);
extern struct fib_table *fib_hash_table(u32 id);

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int __net_init  fib_proc_init(struct net *net);
extern void __net_exit fib_proc_exit(struct net *net);
#else
static inline int fib_proc_init(struct net *net)
{
	return 0;
}
static inline void fib_proc_exit(struct net *net)
{
}
#endif

#endif  /* _NET_FIB_H */
