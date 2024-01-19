/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: semantics.
 *
 * Version:	$Id: fib_semantics.c,v 1.19 2002/01/12 07:54:56 davem Exp $
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/init.h>

#include <net/arp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/netlink.h>
#include <net/nexthop.h>

#include "fib_lookup.h"

static DEFINE_SPINLOCK(fib_info_lock);
//内核中所有的路由项结构都会链入到 fib_info_hash 队列中便于内核查找
static struct hlist_head *fib_info_hash;
//当设置了路由项的源地址时,对应的路由项结构才会链入 fib_info_laddrhash 队列中。当fib_info.fib_prefsrc不为空时,对应的路由项结构才会链入 fib_info_laddrhash 队列中。
static struct hlist_head *fib_info_laddrhash;
//用于路由项fib_info结构队列 fib_info_hash 长度的计数，内核的所有的路由项都保存在fib_info_hash队列中
static unsigned int fib_hash_size;
//全局的fib_info的数量
static unsigned int fib_info_cnt;

#define DEVINDEX_HASHBITS 8
#define DEVINDEX_HASHSIZE (1U << DEVINDEX_HASHBITS)
static struct hlist_head fib_info_devhash[DEVINDEX_HASHSIZE];

#ifdef CONFIG_IP_ROUTE_MULTIPATH

static DEFINE_SPINLOCK(fib_multipath_lock);

#define for_nexthops(fi) { int nhsel; const struct fib_nh * nh; \
for (nhsel=0, nh = (fi)->fib_nh; nhsel < (fi)->fib_nhs; nh++, nhsel++)

#define change_nexthops(fi) { int nhsel; struct fib_nh * nh; \
for (nhsel=0, nh = (struct fib_nh*)((fi)->fib_nh); nhsel < (fi)->fib_nhs; nh++, nhsel++)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

/* Hope, that gcc will optimize it to get rid of dummy loop */

#define for_nexthops(fi) { int nhsel=0; const struct fib_nh * nh = (fi)->fib_nh; \
for (nhsel=0; nhsel < 1; nhsel++)

#define change_nexthops(fi) { int nhsel=0; struct fib_nh * nh = (struct fib_nh*)((fi)->fib_nh); \
for (nhsel=0; nhsel < 1; nhsel++)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define endfor_nexthops(fi) }


static const struct
{
	int	error;
	u8	scope;
} fib_props[RTN_MAX + 1] = {
	{
		.error	= 0,
		.scope	= RT_SCOPE_NOWHERE,
	},	/* RTN_UNSPEC */
	{
		.error	= 0,
		.scope	= RT_SCOPE_UNIVERSE,
	},	/* RTN_UNICAST */
	{
		.error	= 0,
		.scope	= RT_SCOPE_HOST,
	},	/* RTN_LOCAL */
	{
		.error	= 0,
		.scope	= RT_SCOPE_LINK,
	},	/* RTN_BROADCAST */
	{
		.error	= 0,
		.scope	= RT_SCOPE_LINK,
	},	/* RTN_ANYCAST */
	{
		.error	= 0,
		.scope	= RT_SCOPE_UNIVERSE,
	},	/* RTN_MULTICAST */
	{
		.error	= -EINVAL,
		.scope	= RT_SCOPE_UNIVERSE,
	},	/* RTN_BLACKHOLE */
	{
		.error	= -EHOSTUNREACH,
		.scope	= RT_SCOPE_UNIVERSE,
	},	/* RTN_UNREACHABLE */
	{
		.error	= -EACCES,
		.scope	= RT_SCOPE_UNIVERSE,
	},	/* RTN_PROHIBIT */
	{
		.error	= -EAGAIN,
		.scope	= RT_SCOPE_UNIVERSE,
	},	/* RTN_THROW */
	{
		.error	= -EINVAL,
		.scope	= RT_SCOPE_NOWHERE,
	},	/* RTN_NAT */
	{
		.error	= -EINVAL,
		.scope	= RT_SCOPE_NOWHERE,
	},	/* RTN_XRESOLVE */
};


/* Release a nexthop info record */

void free_fib_info(struct fib_info *fi)
{
	if (fi->fib_dead == 0) {
		printk(KERN_WARNING "Freeing alive fib_info %p\n", fi);
		return;
	}
	change_nexthops(fi) {
		if (nh->nh_dev)
			dev_put(nh->nh_dev);
		nh->nh_dev = NULL;
	} endfor_nexthops(fi);
	fib_info_cnt--;
	release_net(fi->fib_net);
	kfree(fi);
}

void fib_release_info(struct fib_info *fi)
{
	spin_lock_bh(&fib_info_lock);
	if (fi && --fi->fib_treeref == 0) {
		hlist_del(&fi->fib_hash);
		if (fi->fib_prefsrc)
			hlist_del(&fi->fib_lhash);
		change_nexthops(fi) {
			if (!nh->nh_dev)
				continue;
			hlist_del(&nh->nh_hash);
		} endfor_nexthops(fi)
		fi->fib_dead = 1;
		fib_info_put(fi);
	}
	spin_unlock_bh(&fib_info_lock);
}

static __inline__ int nh_comp(const struct fib_info *fi, const struct fib_info *ofi)
{
	const struct fib_nh *onh = ofi->fib_nh;

	for_nexthops(fi) {
		if (nh->nh_oif != onh->nh_oif ||
		    nh->nh_gw  != onh->nh_gw ||
		    nh->nh_scope != onh->nh_scope ||
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		    nh->nh_weight != onh->nh_weight ||
#endif
#ifdef CONFIG_NET_CLS_ROUTE
		    nh->nh_tclassid != onh->nh_tclassid ||
#endif
		    ((nh->nh_flags^onh->nh_flags)&~RTNH_F_DEAD))
			return -1;
		onh++;
	} endfor_nexthops(fi);
	return 0;
}

static inline unsigned int fib_devindex_hashfn(unsigned int val)
{
	unsigned int mask = DEVINDEX_HASHSIZE - 1;

	return (val ^
		(val >> DEVINDEX_HASHBITS) ^
		(val >> (DEVINDEX_HASHBITS * 2))) & mask;
}

static inline unsigned int fib_info_hashfn(const struct fib_info *fi)
{
	unsigned int mask = (fib_hash_size - 1);
	unsigned int val = fi->fib_nhs;

	val ^= fi->fib_protocol;
	val ^= (__force u32)fi->fib_prefsrc;
	val ^= fi->fib_priority;
	for_nexthops(fi) {
		val ^= fib_devindex_hashfn(nh->nh_oif);
	} endfor_nexthops(fi)

	return (val ^ (val >> 7) ^ (val >> 12)) & mask;
}

static struct fib_info *fib_find_info(const struct fib_info *nfi)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct fib_info *fi;
	unsigned int hash;

	hash = fib_info_hashfn(nfi);
	head = &fib_info_hash[hash];

	hlist_for_each_entry(fi, node, head, fib_hash) {
		if (fi->fib_net != nfi->fib_net)
			continue;
		if (fi->fib_nhs != nfi->fib_nhs)
			continue;
		if (nfi->fib_protocol == fi->fib_protocol &&
		    nfi->fib_prefsrc == fi->fib_prefsrc &&
		    nfi->fib_priority == fi->fib_priority &&
		    memcmp(nfi->fib_metrics, fi->fib_metrics,
			   sizeof(fi->fib_metrics)) == 0 &&
		    ((nfi->fib_flags^fi->fib_flags)&~RTNH_F_DEAD) == 0 &&
		    (nfi->fib_nhs == 0 || nh_comp(fi, nfi) == 0))
			return fi;
	}

	return NULL;
}

/* Check, that the gateway is already configured.
   Used only by redirect accept routine.
 */

int ip_fib_check_default(__be32 gw, struct net_device *dev)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct fib_nh *nh;
	unsigned int hash;

	spin_lock(&fib_info_lock);

	hash = fib_devindex_hashfn(dev->ifindex);
	head = &fib_info_devhash[hash];
	hlist_for_each_entry(nh, node, head, nh_hash) {
		if (nh->nh_dev == dev &&
		    nh->nh_gw == gw &&
		    !(nh->nh_flags&RTNH_F_DEAD)) {
			spin_unlock(&fib_info_lock);
			return 0;
		}
	}

	spin_unlock(&fib_info_lock);

	return -1;
}

static inline size_t fib_nlmsg_size(struct fib_info *fi)
{
	size_t payload = NLMSG_ALIGN(sizeof(struct rtmsg))
			 + nla_total_size(4) /* RTA_TABLE */
			 + nla_total_size(4) /* RTA_DST */
			 + nla_total_size(4) /* RTA_PRIORITY */
			 + nla_total_size(4); /* RTA_PREFSRC */

	/* space for nested metrics */
	payload += nla_total_size((RTAX_MAX * nla_total_size(4)));

	if (fi->fib_nhs) {
		/* Also handles the special case fib_nhs == 1 */

		/* each nexthop is packed in an attribute */
		size_t nhsize = nla_total_size(sizeof(struct rtnexthop));

		/* may contain flow and gateway attribute */
		nhsize += 2 * nla_total_size(4);

		/* all nexthops are packed in a nested attribute */
		payload += nla_total_size(fi->fib_nhs * nhsize);
	}

	return payload;
}

void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
	       int dst_len, u32 tb_id, struct nl_info *info,
	       unsigned int nlm_flags)
{
	struct sk_buff *skb;
	u32 seq = info->nlh ? info->nlh->nlmsg_seq : 0;
	int err = -ENOBUFS;

	skb = nlmsg_new(fib_nlmsg_size(fa->fa_info), GFP_KERNEL);
	if (skb == NULL)
		goto errout;

	err = fib_dump_info(skb, info->pid, seq, event, tb_id,
			    fa->fa_type, fa->fa_scope, key, dst_len,
			    fa->fa_tos, fa->fa_info, nlm_flags);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in fib_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	err = rtnl_notify(skb, info->nl_net, info->pid, RTNLGRP_IPV4_ROUTE,
			  info->nlh, GFP_KERNEL);
errout:
	if (err < 0)
		rtnl_set_sk_err(info->nl_net, RTNLGRP_IPV4_ROUTE, err);
}

/* Return the first fib alias matching TOS with
 * priority less than or equal to PRIO.找到首个比tos小，且优先级大于或等于prio的路由表别名
 */
struct fib_alias *fib_find_alias(struct list_head *fah, u8 tos, u32 prio)
{
	if (fah) {
		struct fib_alias *fa;
		list_for_each_entry(fa, fah, fa_list) {
			if (fa->fa_tos > tos)
				continue;
			if (fa->fa_info->fib_priority >= prio ||
			    fa->fa_tos < tos)
				return fa;
		}
	}
	return NULL;
}

int fib_detect_death(struct fib_info *fi, int order,
		     struct fib_info **last_resort, int *last_idx, int dflt)
{
	struct neighbour *n;
	int state = NUD_NONE;

	n = neigh_lookup(&arp_tbl, &fi->fib_nh[0].nh_gw, fi->fib_dev);
	if (n) {
		state = n->nud_state;
		neigh_release(n);
	}
	if (state==NUD_REACHABLE)
		return 0;
	if ((state&NUD_VALID) && order != dflt)
		return 0;
	if ((state&NUD_VALID) ||
	    (*last_idx<0 && order > dflt)) {
		*last_resort = fi;
		*last_idx = order;
	}
	return 1;
}

#ifdef CONFIG_IP_ROUTE_MULTIPATH

static int fib_count_nexthops(struct rtnexthop *rtnh, int remaining)
{
	int nhs = 0;

	while (rtnh_ok(rtnh, remaining)) {
		nhs++;
		rtnh = rtnh_next(rtnh, &remaining);
	}

	/* leftover implies invalid nexthop configuration, discard it */
	return remaining > 0 ? 0 : nhs;
}
//函数的主要作用:将rtnh的属性结构中的内容复制到fi.fib_nh中
static int fib_get_nhs(struct fib_info *fi, struct rtnexthop *rtnh,
		       int remaining, struct fib_config *cfg)
{
	change_nexthops(fi) {//依次取出每个跳转结构
		int attrlen;

		if (!rtnh_ok(rtnh, remaining))//范围控制
			return -EINVAL;

		nh->nh_flags = (cfg->fc_flags & ~0xFF) | rtnh->rtnh_flags;
		nh->nh_oif = rtnh->rtnh_ifindex;
		nh->nh_weight = rtnh->rtnh_hops + 1;
		//检查属性结构后面是否还有内容
		attrlen = rtnh_attrlen(rtnh);
		if (attrlen > 0) {
			struct nlattr *nla, *attrs = rtnh_attrs(rtnh);
			//取得属性数据中的网关地址
			nla = nla_find(attrs, attrlen, RTA_GATEWAY);
			nh->nh_gw = nla ? nla_get_be32(nla) : 0;
#ifdef CONFIG_NET_CLS_ROUTE
			nla = nla_find(attrs, attrlen, RTA_FLOW);
			nh->nh_tclassid = nla ? nla_get_u32(nla) : 0;
#endif
		}

		rtnh = rtnh_next(rtnh, &remaining);
	} endfor_nexthops(fi);

	return 0;
}

#endif

int fib_nh_match(struct fib_config *cfg, struct fib_info *fi)
{
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	struct rtnexthop *rtnh;
	int remaining;
#endif

	if (cfg->fc_priority && cfg->fc_priority != fi->fib_priority)
		return 1;

	if (cfg->fc_oif || cfg->fc_gw) {
		if ((!cfg->fc_oif || cfg->fc_oif == fi->fib_nh->nh_oif) &&
		    (!cfg->fc_gw  || cfg->fc_gw == fi->fib_nh->nh_gw))
			return 0;
		return 1;
	}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (cfg->fc_mp == NULL)
		return 0;

	rtnh = cfg->fc_mp;
	remaining = cfg->fc_mp_len;

	for_nexthops(fi) {
		int attrlen;

		if (!rtnh_ok(rtnh, remaining))
			return -EINVAL;

		if (rtnh->rtnh_ifindex && rtnh->rtnh_ifindex != nh->nh_oif)
			return 1;

		attrlen = rtnh_attrlen(rtnh);
		if (attrlen < 0) {
			struct nlattr *nla, *attrs = rtnh_attrs(rtnh);

			nla = nla_find(attrs, attrlen, RTA_GATEWAY);
			if (nla && nla_get_be32(nla) != nh->nh_gw)
				return 1;
#ifdef CONFIG_NET_CLS_ROUTE
			nla = nla_find(attrs, attrlen, RTA_FLOW);
			if (nla && nla_get_u32(nla) != nh->nh_tclassid)
				return 1;
#endif
		}

		rtnh = rtnh_next(rtnh, &remaining);
	} endfor_nexthops(fi);
#endif
	return 0;
}


/*
   Picture
   -------

   Semantics of nexthop is very messy by historical reasons.
   We have to take into account, that:
   a) gateway can be actually local interface address,
      so that gatewayed route is direct.
   b) gateway must be on-link address, possibly
      described not by an ifaddr, but also by a direct route.
   c) If both gateway and interface are specified, they should not
      contradict.
   d) If we use tunnel routes, gateway could be not on-link.

   Attempt to reconcile all of these (alas, self-contradictory) conditions
   results in pretty ugly and hairy code with obscure logic.

   I chose to generalized it instead, so that the size
   of code does not increase practically, but it becomes
   much more general.
   Every prefix is assigned a "scope" value: "host" is local address,
   "link" is direct route,
   [ ... "site" ... "interior" ... ]
   and "universe" is true gateway route with global meaning.

   Every prefix refers to a set of "nexthop"s (gw, oif),
   where gw must have narrower scope. This recursion stops
   when gw has LOCAL scope or if "nexthop" is declared ONLINK,
   which means that gw is forced to be on link.

   Code is still hairy, but now it is apparently logically
   consistent and very flexible. F.e. as by-product it allows
   to co-exists in peace independent exterior and interior
   routing processes.

   Normally it looks as following.

   {universe prefix}  -> (gw, oif) [scope link]
			  |
			  |-> {link prefix} -> (gw, oif) [scope local]
						|
						|-> {local prefix} (terminal node)
 */

static int fib_check_nh(struct fib_config *cfg, struct fib_info *fi,
			struct fib_nh *nh)
{
	int err;
	struct net *net;

	net = cfg->fc_nlinfo.nl_net;
	if (nh->nh_gw) {//如果下一跳是网关
		struct fib_result res;

#ifdef CONFIG_IP_ROUTE_PERVASIVE
		if (nh->nh_flags&RTNH_F_PERVASIVE)
			return 0;
#endif
		if (nh->nh_flags&RTNH_F_ONLINK) {//指定了onlink参数，告诉路由网关就直连在这个网卡上。一般用于路由通向虚拟设备
			struct net_device *dev;

			if (cfg->fc_scope >= RT_SCOPE_LINK)//是否在本地子网范围内
				return -EINVAL;
			if (inet_addr_type(net, nh->nh_gw) != RTN_UNICAST)//检查是否单播
				return -EINVAL;
			if ((dev = __dev_get_by_index(net, nh->nh_oif)) == NULL)//通过index查询到出口网卡的信息
				return -ENODEV;
			if (!(dev->flags&IFF_UP))
				return -ENETDOWN;
			nh->nh_dev = dev;//保存出口网卡信息
			dev_hold(dev);//增加引用计数
			nh->nh_scope = RT_SCOPE_LINK;
			return 0;
		}
		//走到该位置，说明非直连，需要查明网关的地址类型
		{
			struct flowi fl = {
				.nl_u = {
					.ip4_u = {
						.daddr = nh->nh_gw,//网关地址，即目的地址
						.scope = cfg->fc_scope + 1,
					},
				},
				.oif = nh->nh_oif,//出接口
			};

			/* It is not necessary, but requires a bit of thinking */
			if (fl.fl4_scope < RT_SCOPE_LINK)
				fl.fl4_scope = RT_SCOPE_LINK;
			if ((err = fib_lookup(net, &fl, &res)) != 0)//查询路由
				return err;
		}
		err = -EINVAL;
		if (res.type != RTN_UNICAST && res.type != RTN_LOCAL)
			goto out;
		nh->nh_scope = res.scope;
		nh->nh_oif = FIB_RES_OIF(res);
		if ((nh->nh_dev = FIB_RES_DEV(res)) == NULL)
			goto out;
		dev_hold(nh->nh_dev);
		err = -ENETDOWN;
		if (!(nh->nh_dev->flags & IFF_UP))
			goto out;
		err = 0;
out:
		fib_res_put(&res);
		return err;
	} else {
		struct in_device *in_dev;

		if (nh->nh_flags&(RTNH_F_PERVASIVE|RTNH_F_ONLINK))
			return -EINVAL;

		in_dev = inetdev_by_index(net, nh->nh_oif);
		if (in_dev == NULL)
			return -ENODEV;
		if (!(in_dev->dev->flags&IFF_UP)) {
			in_dev_put(in_dev);
			return -ENETDOWN;
		}
		nh->nh_dev = in_dev->dev;
		dev_hold(nh->nh_dev);
		nh->nh_scope = RT_SCOPE_HOST;
		in_dev_put(in_dev);
	}
	return 0;
}

static inline unsigned int fib_laddr_hashfn(__be32 val)
{
	unsigned int mask = (fib_hash_size - 1);

	return ((__force u32)val ^ ((__force u32)val >> 7) ^ ((__force u32)val >> 14)) & mask;
}

static struct hlist_head *fib_hash_alloc(int bytes)
{
	if (bytes <= PAGE_SIZE)
		return kzalloc(bytes, GFP_KERNEL);
	else
		return (struct hlist_head *)
			__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(bytes));
}

static void fib_hash_free(struct hlist_head *hash, int bytes)
{
	if (!hash)
		return;

	if (bytes <= PAGE_SIZE)
		kfree(hash);
	else
		free_pages((unsigned long) hash, get_order(bytes));
}

static void fib_hash_move(struct hlist_head *new_info_hash,
			  struct hlist_head *new_laddrhash,
			  unsigned int new_size)
{
	struct hlist_head *old_info_hash, *old_laddrhash;
	unsigned int old_size = fib_hash_size;
	unsigned int i, bytes;

	spin_lock_bh(&fib_info_lock);
	old_info_hash = fib_info_hash;//记录旧的hash头位置
	old_laddrhash = fib_info_laddrhash;
	fib_hash_size = new_size;

	for (i = 0; i < old_size; i++) {
		//将旧的 fib_info_hash 队列中所有的路由信息结构移动到新的队列中
		struct hlist_head *head = &fib_info_hash[i];
		struct hlist_node *node, *n;
		struct fib_info *fi;

		hlist_for_each_entry_safe(fi, node, n, head, fib_hash) {
			struct hlist_head *dest;
			unsigned int new_hash;

			hlist_del(&fi->fib_hash);//旧队列摘链

			new_hash = fib_info_hashfn(fi);
			dest = &new_info_hash[new_hash];
			hlist_add_head(&fi->fib_hash, dest);//链入新队列
		}
	}
	fib_info_hash = new_info_hash;//调整全局的 fibinfo hash 队列头指针，指向新队列

	for (i = 0; i < old_size; i++) {
		//将旧的 fib_info_laddrhash队列中所有的路由信息结构移动到新的队列中
		struct hlist_head *lhead = &fib_info_laddrhash[i];
		struct hlist_node *node, *n;
		struct fib_info *fi;

		hlist_for_each_entry_safe(fi, node, n, lhead, fib_lhash) {
			struct hlist_head *ldest;
			unsigned int new_hash;

			hlist_del(&fi->fib_lhash);//旧队列摘链
			//重新计算hash值
			new_hash = fib_laddr_hashfn(fi->fib_prefsrc);
			ldest = &new_laddrhash[new_hash];
			hlist_add_head(&fi->fib_lhash, ldest);//链入新队列
		}
	}
	fib_info_laddrhash = new_laddrhash;//调整全局的 fibinfo laddrhash 队列头指针，指向新队列

	spin_unlock_bh(&fib_info_lock);

	bytes = old_size * sizeof(struct hlist_head *);
	//释放旧队列空间
	fib_hash_free(old_info_hash, bytes);
	fib_hash_free(old_laddrhash, bytes);
}

struct fib_info *fib_create_info(struct fib_config *cfg)
{
	int err;
	struct fib_info *fi = NULL;
	struct fib_info *ofi;
	int nhs = 1;
	struct net *net = cfg->fc_nlinfo.nl_net;

	/* Fast check to catch the most weird cases */
	if (fib_props[cfg->fc_type].scope > cfg->fc_scope)
		goto err_inval;

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (cfg->fc_mp) {
		nhs = fib_count_nexthops(cfg->fc_mp, cfg->fc_mp_len);//获取nexthop的数量
		if (nhs == 0)
			goto err_inval;
	}
#endif

	err = -ENOBUFS;
	if (fib_info_cnt >= fib_hash_size) {//总路由项超过了队列大小，进行扩容
		unsigned int new_size = fib_hash_size << 1;//翻倍
		struct hlist_head *new_info_hash;
		struct hlist_head *new_laddrhash;
		unsigned int bytes;

		if (!new_size)
			new_size = 1;
		bytes = new_size * sizeof(struct hlist_head *);
		new_info_hash = fib_hash_alloc(bytes);
		new_laddrhash = fib_hash_alloc(bytes);
		if (!new_info_hash || !new_laddrhash) {
			fib_hash_free(new_info_hash, bytes);
			fib_hash_free(new_laddrhash, bytes);
		} else
			fib_hash_move(new_info_hash, new_laddrhash, new_size);//调用fibhash_move)将全部的 fib info路由信息从旧的哈希表队列中摘下,然后链人到两个刚刚创建的哈希表队列中

		if (!fib_hash_size)
			goto failure;
	}

	fi = kzalloc(sizeof(*fi)+nhs*sizeof(struct fib_nh), GFP_KERNEL);
	if (fi == NULL)
		goto failure;
	fib_info_cnt++;//递增路由信息结构的计数器

	fi->fib_net = hold_net(net);
	fi->fib_protocol = cfg->fc_protocol;
	fi->fib_flags = cfg->fc_flags;
	fi->fib_priority = cfg->fc_priority;
	fi->fib_prefsrc = cfg->fc_prefsrc;

	fi->fib_nhs = nhs;
	change_nexthops(fi) {
		nh->nh_parent = fi;//让所有下一跳转结构都来“结亲”
	} endfor_nexthops(fi)

	if (cfg->fc_mx) {//如果指定了netlink的属性队列
		struct nlattr *nla;
		int remaining;
		//循环对取得每个属性结构
		nla_for_each_attr(nla, cfg->fc_mx, cfg->fc_mx_len, remaining) {
			int type = nla_type(nla);//取得属性中记录的类型值，例如时MSS RTT MTU等

			if (type) {
				if (type > RTAX_MAX)
					goto err_inval;
				fi->fib_metrics[type - 1] = nla_get_u32(nla);//记录属性结构装载的数据地址
			}
		}
	}

	if (cfg->fc_mp) {//如果指定了“下一个跳转”结构队列
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		err = fib_get_nhs(fi, cfg->fc_mp, cfg->fc_mp_len, cfg);
		if (err != 0)
			goto failure;
		if (cfg->fc_oif && fi->fib_nh->nh_oif != cfg->fc_oif)
			goto err_inval;
		if (cfg->fc_gw && fi->fib_nh->nh_gw != cfg->fc_gw)
			goto err_inval;
#ifdef CONFIG_NET_CLS_ROUTE
		if (cfg->fc_flow && fi->fib_nh->nh_tclassid != cfg->fc_flow)
			goto err_inval;
#endif
#else
		goto err_inval;
#endif
	} else {//分配默认nexthop
		struct fib_nh *nh = fi->fib_nh;

		nh->nh_oif = cfg->fc_oif;
		nh->nh_gw = cfg->fc_gw;
		nh->nh_flags = cfg->fc_flags;
#ifdef CONFIG_NET_CLS_ROUTE
		nh->nh_tclassid = cfg->fc_flow;
#endif
#ifdef CONFIG_IP_ROUTE_MULTIPATH
		nh->nh_weight = 1;
#endif
	}

	if (fib_props[cfg->fc_type].error) {
		if (cfg->fc_gw || cfg->fc_oif || cfg->fc_mp)
			goto err_inval;
		goto link_it;
	}

	if (cfg->fc_scope > RT_SCOPE_HOST)
		goto err_inval;

	if (cfg->fc_scope == RT_SCOPE_HOST) {//路由范围是否属本机范围
		struct fib_nh *nh = fi->fib_nh;

		/* Local address is added. 检查跳转次数和网关地址*/
		if (nhs != 1 || nh->nh_gw)
			goto err_inval;
		nh->nh_scope = RT_SCOPE_NOWHERE;//修改跳转范围，就在本地那也不去
		nh->nh_dev = dev_get_by_index(net, fi->fib_nh->nh_oif);//通过索引获取设备
		err = -ENODEV;
		if (nh->nh_dev == NULL)
			goto failure;
	} else {//路由范围不是本机范围
		change_nexthops(fi) {
			if ((err = fib_check_nh(cfg, fi, nh)) != 0)//检查每一个跳转地址的“合法性
				goto failure;
		} endfor_nexthops(fi)
	}

	if (fi->fib_prefsrc) {//如果指定了路由源地址则检查其地址类型
		if (cfg->fc_type != RTN_LOCAL || !cfg->fc_dst ||
		    fi->fib_prefsrc != cfg->fc_dst)
			if (inet_addr_type(net, fi->fib_prefsrc) != RTN_LOCAL)
				goto err_inval;
	}

link_it:
	if ((ofi = fib_find_info(fi)) != NULL) {//检查是否存在相同的路由信息结构
		fi->fib_dead = 1;
		free_fib_info(fi);
		ofi->fib_treeref++;
		return ofi;//如果存在旧的路由信息结构，将它作为使用对象
	}
	//没有旧的路由信息结构，使用新建的
	fi->fib_treeref++;
	atomic_inc(&fi->fib_clntref);
	spin_lock_bh(&fib_info_lock);
	hlist_add_head(&fi->fib_hash,
		       &fib_info_hash[fib_info_hashfn(fi)]);//链入路由信息结构队列
	if (fi->fib_prefsrc) {
		struct hlist_head *head;

		head = &fib_info_laddrhash[fib_laddr_hashfn(fi->fib_prefsrc)];//如果指定了 IP 地址，还要链人另一个路由地址队列
		hlist_add_head(&fi->fib_lhash, head);
	}
	change_nexthops(fi) {//循环取得路由信息中的每一个跳转结构
		struct hlist_head *head;
		unsigned int hash;

		if (!nh->nh_dev)//检查跳转结构是否指定了跳转设备
			continue;
		hash = fib_devindex_hashfn(nh->nh_dev->ifindex);//确定设备的哈希值
		head = &fib_info_devhash[hash];//在路由设备的哈希数组中找到队列头
		hlist_add_head(&nh->nh_hash, head);//链入路由设备队列
	} endfor_nexthops(fi)
	spin_unlock_bh(&fib_info_lock);
	return fi;

err_inval:
	err = -EINVAL;

failure:
	if (fi) {
		fi->fib_dead = 1;//如果路由信息已经处于删除状态则释放它
		free_fib_info(fi);
	}

	return ERR_PTR(err);
}

/* Note! fib_semantic_match intentionally uses  RCU list functions. */
/*
head: fib_alias 队列
flp: 匹配条件
res：匹配结果
zone: 上层的hashkey
mask：掩码
prefixlen: 掩码长度
*/
int fib_semantic_match(struct list_head *head, const struct flowi *flp,
		       struct fib_result *res, __be32 zone, __be32 mask,
			int prefixlen)
{
	struct fib_alias *fa;
	int nh_sel = 0;
	//遍历fib_alias队列
	list_for_each_entry_rcu(fa, head, fa_list) {
		int err;
		//1. tos值必须要匹配
		if (fa->fa_tos &&
		    fa->fa_tos != flp->fl4_tos)
			continue;
		//2. scope值必须大于匹配的scope值
		if (fa->fa_scope < flp->fl4_scope)
			continue;

		fa->fa_state |= FA_S_ACCESSED;//表示已经访问了

		err = fib_props[fa->fa_type].error;//以路由别名的 fa_type,即路由类型为下标取出数组中的错误码err,如果错误码是0则表示支持该路由类型
		if (err == 0) {
			struct fib_info *fi = fa->fa_info;//具体的路由项

			if (fi->fib_flags & RTNH_F_DEAD)//下一跳是否正常
				continue;
			// 出接口是否一致
			switch (fa->fa_type) {
			case RTN_UNICAST:
			case RTN_LOCAL:
			case RTN_BROADCAST:
			case RTN_ANYCAST:
			case RTN_MULTICAST:
				for_nexthops(fi) {
					if (nh->nh_flags&RTNH_F_DEAD)//检查是否处于移除状态
						continue;
					if (!flp->oif || flp->oif == nh->nh_oif)//判断出接口是否一致，一致说明匹配上
						break;
				}
#ifdef CONFIG_IP_ROUTE_MULTIPATH
				if (nhsel < fi->fib_nhs) {
					nh_sel = nhsel;
					goto out_fill_res;
				}
#else
				if (nhsel < 1) {//小于1说明匹配上了，大于1 说明没有找到路由
					goto out_fill_res;
				}
#endif
				endfor_nexthops(fi);
				continue;

			default:
				printk(KERN_WARNING "fib_semantic_match bad type %#x\n",
					fa->fa_type);
				return -EINVAL;
			}
		}
		return err;
	}
	return 1;

out_fill_res:
	res->prefixlen = prefixlen;
	res->nh_sel = nh_sel;
	res->type = fa->fa_type;
	res->scope = fa->fa_scope;
	res->fi = fa->fa_info;
	atomic_inc(&res->fi->fib_clntref);
	return 0;
}

/* Find appropriate source address to this destination */

__be32 __fib_res_prefsrc(struct fib_result *res)
{
	return inet_select_addr(FIB_RES_DEV(*res), FIB_RES_GW(*res), res->scope);
}

int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
		  u32 tb_id, u8 type, u8 scope, __be32 dst, int dst_len, u8 tos,
		  struct fib_info *fi, unsigned int flags)
{
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*rtm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = dst_len;
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = tos;
	if (tb_id < 256)
		rtm->rtm_table = tb_id;
	else
		rtm->rtm_table = RT_TABLE_COMPAT;
	NLA_PUT_U32(skb, RTA_TABLE, tb_id);
	rtm->rtm_type = type;
	rtm->rtm_flags = fi->fib_flags;
	rtm->rtm_scope = scope;
	rtm->rtm_protocol = fi->fib_protocol;

	if (rtm->rtm_dst_len)
		NLA_PUT_BE32(skb, RTA_DST, dst);

	if (fi->fib_priority)
		NLA_PUT_U32(skb, RTA_PRIORITY, fi->fib_priority);

	if (rtnetlink_put_metrics(skb, fi->fib_metrics) < 0)
		goto nla_put_failure;

	if (fi->fib_prefsrc)
		NLA_PUT_BE32(skb, RTA_PREFSRC, fi->fib_prefsrc);

	if (fi->fib_nhs == 1) {
		if (fi->fib_nh->nh_gw)
			NLA_PUT_BE32(skb, RTA_GATEWAY, fi->fib_nh->nh_gw);

		if (fi->fib_nh->nh_oif)
			NLA_PUT_U32(skb, RTA_OIF, fi->fib_nh->nh_oif);
#ifdef CONFIG_NET_CLS_ROUTE
		if (fi->fib_nh[0].nh_tclassid)
			NLA_PUT_U32(skb, RTA_FLOW, fi->fib_nh[0].nh_tclassid);
#endif
	}
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (fi->fib_nhs > 1) {
		struct rtnexthop *rtnh;
		struct nlattr *mp;

		mp = nla_nest_start(skb, RTA_MULTIPATH);
		if (mp == NULL)
			goto nla_put_failure;

		for_nexthops(fi) {
			rtnh = nla_reserve_nohdr(skb, sizeof(*rtnh));
			if (rtnh == NULL)
				goto nla_put_failure;

			rtnh->rtnh_flags = nh->nh_flags & 0xFF;
			rtnh->rtnh_hops = nh->nh_weight - 1;
			rtnh->rtnh_ifindex = nh->nh_oif;

			if (nh->nh_gw)
				NLA_PUT_BE32(skb, RTA_GATEWAY, nh->nh_gw);
#ifdef CONFIG_NET_CLS_ROUTE
			if (nh->nh_tclassid)
				NLA_PUT_U32(skb, RTA_FLOW, nh->nh_tclassid);
#endif
			/* length of rtnetlink header + attributes */
			rtnh->rtnh_len = nlmsg_get_pos(skb) - (void *) rtnh;
		} endfor_nexthops(fi);

		nla_nest_end(skb, mp);
	}
#endif
	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/*
   Update FIB if:
   - local address disappeared -> we must delete all the entries
     referring to it.
   - device went down -> we must shutdown all nexthops going via it.
 */
int fib_sync_down_addr(struct net *net, __be32 local)
{
	int ret = 0;
	unsigned int hash = fib_laddr_hashfn(local);
	struct hlist_head *head = &fib_info_laddrhash[hash];
	struct hlist_node *node;
	struct fib_info *fi;

	if (fib_info_laddrhash == NULL || local == 0)
		return 0;

	hlist_for_each_entry(fi, node, head, fib_lhash) {
		if (fi->fib_net != net)
			continue;
		if (fi->fib_prefsrc == local) {
			fi->fib_flags |= RTNH_F_DEAD;
			ret++;
		}
	}
	return ret;
}

int fib_sync_down_dev(struct net_device *dev, int force)
{
	int ret = 0;
	int scope = RT_SCOPE_NOWHERE;
	struct fib_info *prev_fi = NULL;
	unsigned int hash = fib_devindex_hashfn(dev->ifindex);
	struct hlist_head *head = &fib_info_devhash[hash];
	struct hlist_node *node;
	struct fib_nh *nh;

	if (force)
		scope = -1;

	hlist_for_each_entry(nh, node, head, nh_hash) {
		struct fib_info *fi = nh->nh_parent;
		int dead;

		BUG_ON(!fi->fib_nhs);
		if (nh->nh_dev != dev || fi == prev_fi)
			continue;
		prev_fi = fi;
		dead = 0;
		change_nexthops(fi) {
			if (nh->nh_flags&RTNH_F_DEAD)
				dead++;
			else if (nh->nh_dev == dev &&
					nh->nh_scope != scope) {
				nh->nh_flags |= RTNH_F_DEAD;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
				spin_lock_bh(&fib_multipath_lock);
				fi->fib_power -= nh->nh_power;
				nh->nh_power = 0;
				spin_unlock_bh(&fib_multipath_lock);
#endif
				dead++;
			}
#ifdef CONFIG_IP_ROUTE_MULTIPATH
			if (force > 1 && nh->nh_dev == dev) {
				dead = fi->fib_nhs;
				break;
			}
#endif
		} endfor_nexthops(fi)
		if (dead == fi->fib_nhs) {
			fi->fib_flags |= RTNH_F_DEAD;
			ret++;
		}
	}

	return ret;
}

#ifdef CONFIG_IP_ROUTE_MULTIPATH

/*
   Dead device goes up. We wake up dead nexthops.
   It takes sense only on multipath routes.
 */

int fib_sync_up(struct net_device *dev)
{
	struct fib_info *prev_fi;
	unsigned int hash;
	struct hlist_head *head;
	struct hlist_node *node;
	struct fib_nh *nh;
	int ret;

	if (!(dev->flags&IFF_UP))
		return 0;

	prev_fi = NULL;
	hash = fib_devindex_hashfn(dev->ifindex);
	head = &fib_info_devhash[hash];
	ret = 0;

	hlist_for_each_entry(nh, node, head, nh_hash) {
		struct fib_info *fi = nh->nh_parent;
		int alive;

		BUG_ON(!fi->fib_nhs);
		if (nh->nh_dev != dev || fi == prev_fi)
			continue;

		prev_fi = fi;
		alive = 0;
		change_nexthops(fi) {
			if (!(nh->nh_flags&RTNH_F_DEAD)) {
				alive++;
				continue;
			}
			if (nh->nh_dev == NULL || !(nh->nh_dev->flags&IFF_UP))
				continue;
			if (nh->nh_dev != dev || !__in_dev_get_rtnl(dev))
				continue;
			alive++;
			spin_lock_bh(&fib_multipath_lock);
			nh->nh_power = 0;
			nh->nh_flags &= ~RTNH_F_DEAD;
			spin_unlock_bh(&fib_multipath_lock);
		} endfor_nexthops(fi)

		if (alive > 0) {
			fi->fib_flags &= ~RTNH_F_DEAD;
			ret++;
		}
	}

	return ret;
}

/*
   The algorithm is suboptimal, but it provides really
   fair weighted route distribution.
 */

void fib_select_multipath(const struct flowi *flp, struct fib_result *res)
{
	struct fib_info *fi = res->fi;
	int w;

	spin_lock_bh(&fib_multipath_lock);
	if (fi->fib_power <= 0) {//调整路由信息的跳转能力值
		int power = 0;
		change_nexthops(fi) {
			if (!(nh->nh_flags&RTNH_F_DEAD)) {
				power += nh->nh_weight;//记录每个跳转结构的压力值
				nh->nh_power = nh->nh_weight;// 能力来源于压力
			}
		} endfor_nexthops(fi);
		fi->fib_power = power;//记录下能力统计结果
		if (power <= 0) {
			spin_unlock_bh(&fib_multipath_lock);
			/* Race condition: route has just become dead. */
			res->nh_sel = 0;//清除跳转计数
			return;
		}
	}


	/* w should be random number [0..fi->fib_power-1],
	   it is pretty bad approximation.
	 */

	w = jiffies % fi->fib_power;

	change_nexthops(fi) {
		if (!(nh->nh_flags&RTNH_F_DEAD) && nh->nh_power) {
			if ((w -= nh->nh_power) <= 0) {//在能力范围统计跳转次数
				nh->nh_power--;
				fi->fib_power--;
				res->nh_sel = nhsel;//记录跳转次数
				spin_unlock_bh(&fib_multipath_lock);
				return;
			}
		}
	} endfor_nexthops(fi);

	/* Race condition: route has just become dead. */
	res->nh_sel = 0;
	spin_unlock_bh(&fib_multipath_lock);
}
#endif
