/* linux/net/ipv4/arp.c
 *
 * Version:	$Id: arp.c,v 1.99 2001/08/30 22:55:42 davem Exp $
 *
 * Copyright (C) 1994 by Florian  La Roche
 *
 * This module implements the Address Resolution Protocol ARP (RFC 826),
 * which is used to convert IP addresses (or in the future maybe other
 * high-level addresses) into a low-level hardware address (like an Ethernet
 * address).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Fixes:
 *		Alan Cox	:	Removed the Ethernet assumptions in
 *					Florian's code
 *		Alan Cox	:	Fixed some small errors in the ARP
 *					logic
 *		Alan Cox	:	Allow >4K in /proc
 *		Alan Cox	:	Make ARP add its own protocol entry
 *		Ross Martin     :       Rewrote arp_rcv() and arp_get_info()
 *		Stephen Henson	:	Add AX25 support to arp_get_info()
 *		Alan Cox	:	Drop data when a device is downed.
 *		Alan Cox	:	Use init_timer().
 *		Alan Cox	:	Double lock fixes.
 *		Martin Seine	:	Move the arphdr structure
 *					to if_arp.h for compatibility.
 *					with BSD based programs.
 *		Andrew Tridgell :       Added ARP netmask code and
 *					re-arranged proxy handling.
 *		Alan Cox	:	Changed to use notifiers.
 *		Niibe Yutaka	:	Reply for this device or proxies only.
 *		Alan Cox	:	Don't proxy across hardware types!
 *		Jonathan Naylor :	Added support for NET/ROM.
 *		Mike Shaver     :       RFC1122 checks.
 *		Jonathan Naylor :	Only lookup the hardware address for
 *					the correct hardware type.
 *		Germano Caronni	:	Assorted subtle races.
 *		Craig Schlenter :	Don't modify permanent entry
 *					during arp_rcv.
 *		Russ Nelson	:	Tidied up a few bits.
 *		Alexey Kuznetsov:	Major changes to caching and behaviour,
 *					eg intelligent arp probing and
 *					generation
 *					of host down events.
 *		Alan Cox	:	Missing unlock in device events.
 *		Eckes		:	ARP ioctl control errors.
 *		Alexey Kuznetsov:	Arp free fix.
 *		Manuel Rodriguez:	Gratuitous ARP.
 *              Jonathan Layes  :       Added arpd support through kerneld
 *                                      message queue (960314)
 *		Mike Shaver	:	/proc/sys/net/ipv4/arp_* support
 *		Mike McLagan    :	Routing by source
 *		Stuart Cheshire	:	Metricom and grat arp fixes
 *					*** FOR 2.1 clean this up ***
 *		Lawrence V. Stefani: (08/12/96) Added FDDI support.
 *		Alan Cox 	:	Took the AP1000 nasty FDDI hack and
 *					folded into the mainstream FDDI code.
 *					Ack spit, Linus how did you allow that
 *					one in...
 *		Jes Sorensen	:	Make FDDI work again in 2.1.x and
 *					clean up the APFDDI & gen. FDDI bits.
 *		Alexey Kuznetsov:	new arp state machine;
 *					now it is in net/core/neighbour.c.
 *		Krzysztof Halasa:	Added Frame Relay ARP support.
 *		Arnaldo C. Melo :	convert /proc/net/arp to seq_file
 *		Shmulik Hen:		Split arp_send to arp_create and
 *					arp_xmit so intermediate drivers like
 *					bonding can change the skb before
 *					sending (e.g. insert 8021q tag).
 *		Harald Welte	:	convert to make use of jenkins hash
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fddidevice.h>
#include <linux/if_arp.h>
#include <linux/trdevice.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ax25.h>
#include <net/netrom.h>
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
#include <net/atmclip.h>
struct neigh_table *clip_tbl_hook;
#endif

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/netfilter_arp.h>

/*
 *	Interface to generic neighbour cache.
 */
static u32 arp_hash(const void *pkey, const struct net_device *dev);
static int arp_constructor(struct neighbour *neigh);
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb);
static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb);
static void parp_redo(struct sk_buff *skb);

static struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

static struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

static struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		dev_queue_xmit,
	.connected_output =	dev_queue_xmit,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

struct neigh_ops arp_broken_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_compat_output,
	.connected_output =	neigh_compat_output,
	.hh_output =		dev_queue_xmit,
	.queue_xmit =		dev_queue_xmit,
};

struct neigh_table arp_tbl = {
	.family =	AF_INET,
	.entry_size =	sizeof(struct neighbour) + 4,// +4 是后面跟了一个IP地址
	.key_len =	4,//IP地址的长度
	.hash =		arp_hash,
	.constructor =	arp_constructor,
	.proxy_redo =	parp_redo,
	.id =		"arp_cache",
	.parms = {
		.tbl =			&arp_tbl,
		.base_reachable_time =	30 * HZ,
		.retrans_time =	1 * HZ,
		.gc_staletime =	60 * HZ,
		.reachable_time =		30 * HZ,
		.delay_probe_time =	5 * HZ,
		.queue_len =		3,
		.ucast_probes =	3,
		.mcast_probes =	3,
		.anycast_delay =	1 * HZ,
		.proxy_delay =		(8 * HZ) / 10,
		.proxy_qlen =		64,
		.locktime =		1 * HZ,
	},
	.gc_interval =	30 * HZ,
	.gc_thresh1 =	128,
	.gc_thresh2 =	512,
	.gc_thresh3 =	1024,
};
//addr是IP地址
int arp_mc_map(__be32 addr, u8 *haddr, struct net_device *dev, int dir)
{
	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		ip_eth_mc_map(addr, haddr);
		return 0;
	case ARPHRD_IEEE802_TR:
		ip_tr_mc_map(addr, haddr);
		return 0;
	case ARPHRD_INFINIBAND:
		ip_ib_mc_map(addr, dev->broadcast, haddr);
		return 0;
	default:
		if (dir) {
			memcpy(haddr, dev->broadcast, dev->addr_len);
			return 0;
		}
	}
	return -EINVAL;
}


static u32 arp_hash(const void *pkey, const struct net_device *dev)
{
	return jhash_2words(*(u32 *)pkey, dev->ifindex, arp_tbl.hash_rnd);
}

static int arp_constructor(struct neighbour *neigh)
{
	__be32 addr = *(__be32*)neigh->primary_key;//获取IP地址
	struct net_device *dev = neigh->dev;//获取网络设备
	struct in_device *in_dev;
	struct neigh_parms *parms;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);//获取设备的配置结构
	if (in_dev == NULL) {
		rcu_read_unlock();
		return -EINVAL;
	}

	neigh->type = inet_addr_type(dev_net(dev), addr);//记录地址类型 RTN_BROADCAST、RTN_LOCAL、RTN_BROADCAST、RTN_UNICAST

	parms = in_dev->arp_parms;//获取配置结构的的邻居参数
	__neigh_parms_put(neigh->parms);//递减原来邻居参数的使用计数
	neigh->parms = neigh_parms_clone(parms);//记录配置结构的邻居参数
	rcu_read_unlock();
	//对于eth，header_ops是eth_header_ops。也就是说不会走到这个位置，而是else分支
	if (!dev->header_ops) {//是否安装了链路层函数表，由驱动安装
		neigh->nud_state = NUD_NOARP;//不需要解析状态
		neigh->ops = &arp_direct_ops;//记录函数表，直接将包发送给底层
		neigh->output = neigh->ops->queue_xmit;//设置发送函数：dev_queue_xmit
	} else {
		/* Good devices (checked by reading texts, but only Ethernet is
		   tested)

		   ARPHRD_ETHER: (ethernet, apfddi)
		   ARPHRD_FDDI: (fddi)
		   ARPHRD_IEEE802: (tr)
		   ARPHRD_METRICOM: (strip)
		   ARPHRD_ARCNET:
		   etc. etc. etc.

		   ARPHRD_IPDDP will also work, if author repairs it.
		   I did not it, because this driver does not work even
		   in old paradigm.
		 */

#if 1
		/* So... these "amateur" devices are hopeless.
		   The only thing, that I can say now:
		   It is very sad that we need to keep ugly obsolete
		   code to make them happy.

		   They should be moved to more reasonable state, now
		   they use rebuild_header INSTEAD OF hard_start_xmit!!!
		   Besides that, they are sort of out of date
		   (a lot of redundant clones/copies, useless in 2.1),
		   I wonder why people believe that they work.
		 */
		switch (dev->type) {//判断网络设备类型
		default:
			break;
		case ARPHRD_ROSE:
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
		case ARPHRD_AX25:
#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
		case ARPHRD_NETROM:
#endif
			neigh->ops = &arp_broken_ops;//记录函数表
			neigh->output = neigh->ops->output;//设置发送函数
			return 0;
#endif
		;}
#endif
		//组播、环回、点对点、广播的都不需要ARP
		if (neigh->type == RTN_MULTICAST) {//组播状态
			neigh->nud_state = NUD_NOARP;
			arp_mc_map(addr, neigh->ha, dev, 1);//设置mac地址。组播mac地址有些特殊，这里把IP地址写入mac地址中
		} else if (dev->flags&(IFF_NOARP|IFF_LOOPBACK)) {//回环设备
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);//直接将设备的地址作为邻居结构的MAC地址
		} else if (neigh->type == RTN_BROADCAST || dev->flags&IFF_POINTOPOINT) {//广播或者点对点设备
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);//复制广播地址。ether1394设备会在初始化的时候将dev->broadcast设置为全0xff
		}
		//设置函数表，不是arp_hh_ops就是arp_generic_ops.对于eth设备，cache函数是eth_header_cache
		if (dev->header_ops->cache)//cache函数将以太头缓存到邻居结构的hh中，数据包发送前，直接拷贝缓存的以太头即可，无需重新组装
			neigh->ops = &arp_hh_ops;//记录函数表。eth会走到这位置
		else
			neigh->ops = &arp_generic_ops;

		if (neigh->nud_state&NUD_VALID)//无效状态
			neigh->output = neigh->ops->connected_output;//设置发送状态
		else
			neigh->output = neigh->ops->output;//使用函数表的发送函数
	}
	return 0;
}

static void arp_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	dst_link_failure(skb);
	kfree_skb(skb);
}

static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	__be32 saddr = 0;
	u8  *dst_ha = NULL;
	struct net_device *dev = neigh->dev;
	__be32 target = *(__be32*)neigh->primary_key;
	int probes = atomic_read(&neigh->probes);
	struct in_device *in_dev = in_dev_get(dev);

	if (!in_dev)
		return;

	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP */
		if (skb && inet_addr_type(dev_net(dev), ip_hdr(skb)->saddr) == RTN_LOCAL)
			saddr = ip_hdr(skb)->saddr;
		break;
	case 1:		/* Restrict announcements of saddr in same subnet */
		if (!skb)
			break;
		saddr = ip_hdr(skb)->saddr;
		if (inet_addr_type(dev_net(dev), saddr) == RTN_LOCAL) {
			/* saddr should be known to target */
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		break;
	}

	if (in_dev)
		in_dev_put(in_dev);
	if (!saddr)
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);

	if ((probes -= neigh->parms->ucast_probes) < 0) {
		if (!(neigh->nud_state&NUD_VALID))
			printk(KERN_DEBUG "trying to ucast probe in NUD_INVALID\n");
		dst_ha = neigh->ha;
		read_lock_bh(&neigh->lock);
	} else if ((probes -= neigh->parms->app_probes) < 0) {
#ifdef CONFIG_ARPD
		neigh_app_ns(neigh);
#endif
		return;
	}

	arp_send(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		 dst_ha, dev->dev_addr, NULL);
	if (dst_ha)
		read_unlock_bh(&neigh->lock);
}

static int arp_ignore(struct in_device *in_dev, __be32 sip, __be32 tip)
{
	int scope;

	switch (IN_DEV_ARP_IGNORE(in_dev)) {
	case 0:	/* 响应任意网卡上接收到的对本机IP地址的arp请求（包括环回网卡上的地址），而不管该目的IP是否在接收网卡上，目的IP有可能在其他网卡上。 */
		return 0;
	case 1:	/* Reply only if tip is configured on the incoming interface只响应目的IP地址为接收网卡上的本地地址的arp请求。 */
		sip = 0;
		scope = RT_SCOPE_HOST;
		break;
	case 2:	/*
		 * Reply only if tip is configured on the incoming interface
		 * and is in same subnet as sip
		 * 只响应目的IP地址为接收网卡上的本地地址的arp请求，并且arp请求的源IP必须和接收网卡同网段。
		 */
		scope = RT_SCOPE_HOST;
		break;
	case 3:	/* Do not reply for scope host addresses 如果ARP请求数据包所请求的IP地址对应的本地地址其作用域（scope）为主机（host），则不回应ARP响应数据包，如果作用域为全局（global）或链路（link），则回应ARP响应数据包*/
		sip = 0;
		scope = RT_SCOPE_LINK;
		break;
	case 4:	/* Reserved */
	case 5:
	case 6:
	case 7:
		return 0;
	case 8:	/* Do not reply不回应所有的arp请求 */
		return 1;
	default:
		return 0;
	}
	return !inet_confirm_addr(in_dev, sip, tip, scope);
}

static int arp_filter(__be32 sip, __be32 tip, struct net_device *dev)
{
	struct flowi fl = { .nl_u = { .ip4_u = { .daddr = sip,
						 .saddr = tip } } };
	struct rtable *rt;
	int flag = 0;
	/*unsigned long now; */

	if (ip_route_output_key(dev_net(dev), &rt, &fl) < 0)
		return 1;
	if (rt->u.dst.dev != dev) {
		NET_INC_STATS_BH(LINUX_MIB_ARPFILTER);
		flag = 1;
	}
	ip_rt_put(rt);
	return flag;
}

/* OBSOLETE FUNCTIONS */

/*
 *	Find an arp mapping in the cache. If not found, post a request.
 *
 *	It is very UGLY routine: it DOES NOT use skb->dst->neighbour,
 *	even if it exists. It is supposed that skb->dev was mangled
 *	by a virtual device (eql, shaper). Nobody but broken devices
 *	is allowed to use this function, it is scheduled to be removed. --ANK
 */

static int arp_set_predefined(int addr_hint, unsigned char * haddr, __be32 paddr, struct net_device * dev)
{
	switch (addr_hint) {
	case RTN_LOCAL:
		printk(KERN_DEBUG "ARP: arp called for own IP address\n");
		memcpy(haddr, dev->dev_addr, dev->addr_len);
		return 1;
	case RTN_MULTICAST:
		arp_mc_map(paddr, haddr, dev, 1);
		return 1;
	case RTN_BROADCAST:
		memcpy(haddr, dev->broadcast, dev->addr_len);
		return 1;
	}
	return 0;
}


int arp_find(unsigned char *haddr, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	__be32 paddr;
	struct neighbour *n;

	if (!skb->dst) {
		printk(KERN_DEBUG "arp_find is called with dst==NULL\n");
		kfree_skb(skb);
		return 1;
	}

	paddr = skb->rtable->rt_gateway;

	if (arp_set_predefined(inet_addr_type(dev_net(dev), paddr), haddr, paddr, dev))
		return 0;

	n = __neigh_lookup(&arp_tbl, &paddr, dev, 1);

	if (n) {
		n->used = jiffies;
		if (n->nud_state&NUD_VALID || neigh_event_send(n, skb) == 0) {
			read_lock_bh(&n->lock);
			memcpy(haddr, n->ha, dev->addr_len);
			read_unlock_bh(&n->lock);
			neigh_release(n);
			return 0;
		}
		neigh_release(n);
	} else
		kfree_skb(skb);
	return 1;
}

/* END OF OBSOLETE FUNCTIONS */
/*
功能:实现路由缓存与邻居项的绑定操作。
1.当该路由缓存项没有关联相应的邻居项时，
  则根据下一跳ip地址，调用__neigh_lookup_errno查找相应的邻居项
  (调用__neigh_lookup_errno后，当邻居项不存在时，则会调用函数neigh_create
  创建邻居项；若存在相应的邻居项，则返回该邻居项)
2.将邻居项与路由缓存项进行关联。
当本地网卡收到需要转发的数据时，其走向如下：
a.调用ip_rcv函数，对三层数据进行处理
b.进入netfilter的prerouting链，进行netfilter的处理（netfliter子系统）
c.netfilter模块准许通过后，则调用ip_rcv_finish继续处理
d.在ip_rcv_finish中，若数据还没有和路由缓存项关联，则调用函数ip_route_input进行路由缓存项以及路由缓存的查找。当路由缓存没有查找到后，
	则会调用ip_route_input_slow进行路由项的查找，若查找到路由项，则会调用ip_mkroute_input创建路由缓存项，并在调用rt_intern_hash中，
	通过arp_bind_neighbour将路由缓存项与邻居项进行绑定，并调用__mkroute_input设置dst的input、output函数，并将skb与路由缓存项进行绑定
e.通过调用dst_input，进入skb->dst->input函数，即2.1中的ip_forward函数。
f.在ip_forward函数中，进行合法性判断后，则会进入netfilter的forward链
g.netfilter通过后，则调用ip_forward_finish，通过dst_output，调用到2.1中的ip_output函数
h.进入netfilter的post链，若准许通过则调用ip_finish_output
i.决定是否进行分段操作，最后调用函数ip_finish_output2
j.在ip_finish_output2里，则会根据数据包关联的路由缓存项，找到缓存项对应的邻居项，并调用neighbour->output，这就进入了邻居子系统了。
k.对于ipv4来书，其output函数为neigh_resolve_output，在该函数里，若判断下一跳地址对应的mac地址还没有解析到，则会调用neigh_event_send更改邻居项的状态，
	以发送arp request报文，并将该数据包存入队列中，等解析到mac地址以后再发送出去；若下一跳对应的mac地址已经解析到，则会调用neigh->ops->queue_xmit将数据发送出去，
	对于ipv4来说即是dev_queue_xmit函数，而在该函数里，则会通过dev->hard_start_xmit调用网卡驱动的发送函数，将数据发送出去。
————————————————
版权声明：本文为CSDN博主「jerry_chg」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/lickylin/article/details/41556363
*/
int arp_bind_neighbour(struct dst_entry *dst)
{
	struct net_device *dev = dst->dev;
	struct neighbour *n = dst->neighbour;

	if (dev == NULL)
		return -EINVAL;
	if (n == NULL) {
		__be32 nexthop = ((struct rtable*)dst)->rt_gateway;
		if (dev->flags&(IFF_LOOPBACK|IFF_POINTOPOINT))
			nexthop = 0;
		n = __neigh_lookup_errno(
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
		    dev->type == ARPHRD_ATM ? clip_tbl_hook :
#endif
		    &arp_tbl, &nexthop, dev);
		if (IS_ERR(n))
			return PTR_ERR(n);
		dst->neighbour = n;
	}
	return 0;
}

/*
 * Check if we can use proxy ARP for this path
 */

static inline int arp_fwd_proxy(struct in_device *in_dev, struct rtable *rt)
{
	struct in_device *out_dev;
	int imi, omi = -1;

	if (!IN_DEV_PROXY_ARP(in_dev))
		return 0;

	if ((imi = IN_DEV_MEDIUM_ID(in_dev)) == 0)
		return 1;
	if (imi == -1)
		return 0;

	/* place to check for proxy_arp for routes */

	if ((out_dev = in_dev_get(rt->u.dst.dev)) != NULL) {
		omi = IN_DEV_MEDIUM_ID(out_dev);
		in_dev_put(out_dev);
	}
	return (omi != imi && omi != -1);
}

/*
 *	Interface to link layer: send routine and receive handler.
 */

/*
 *	Create an arp packet. If (dest_hw == NULL), we create a broadcast
 *	message.
 */
struct sk_buff *arp_create(int type, int ptype, __be32 dest_ip,
			   struct net_device *dev, __be32 src_ip,
			   const unsigned char *dest_hw,
			   const unsigned char *src_hw,
			   const unsigned char *target_hw)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	unsigned char *arp_ptr;

	/*
	 *	Allocate a buffer
	 */
	//分配数据包结构空间,分配缓冲块，其长度包含 ARP 头部长度和以太网头部长度
	skb = alloc_skb(arp_hdr_len(dev) + LL_ALLOCATED_SPACE(dev), GFP_ATOMIC);
	if (skb == NULL)
		return NULL;
	//预留以太网头部
	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	//设置网络层头部指针
	skb_reset_network_header(skb);
	arp = (struct arphdr *) skb_put(skb, arp_hdr_len(dev));//指向数据块中的ARP头部
	skb->dev = dev;//记录设备
	skb->protocol = htons(ETH_P_ARP);//记录协议类型
	if (src_hw == NULL)//没有指定源硬件地址
		src_hw = dev->dev_addr;//使用设备的源硬件地址
	if (dest_hw == NULL)//没有指定目的硬件地址
		dest_hw = dev->broadcast;//使用设备的广播地址，即全0xff，dev初始化的时候会设置为全ff

	/*
	 *	Fill the device header for the ARP frame
	 填充eth头中的mac地址信息，调用eth_header_ops结构中的create()函数
	 */
	if (dev_hard_header(skb, dev, ptype, dest_hw, src_hw, skb->len) < 0)
		goto out;

	/*
	 * Fill out the arp protocol part.
	 *
	 * The arp hardware type should match the device type, except for FDDI,
	 * which (according to RFC 1390) should always equal 1 (Ethernet).
	 */
	/*
	 *	Exceptions everywhere. AX.25 uses the AX.25 PID value not the
	 *	DIX code for the protocol. Make these device structure fields.
	 */
	switch (dev->type) {
	default:
		arp->ar_hrd = htons(dev->type);//记录硬件类型
		arp->ar_pro = htons(ETH_P_IP);//记录协议类型
		break;

#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	case ARPHRD_AX25:
		arp->ar_hrd = htons(ARPHRD_AX25);
		arp->ar_pro = htons(AX25_P_IP);
		break;

#if defined(CONFIG_NETROM) || defined(CONFIG_NETROM_MODULE)
	case ARPHRD_NETROM:
		arp->ar_hrd = htons(ARPHRD_NETROM);
		arp->ar_pro = htons(AX25_P_IP);
		break;
#endif
#endif

#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
		arp->ar_hrd = htons(ARPHRD_ETHER);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
#ifdef CONFIG_TR
	case ARPHRD_IEEE802_TR:
		arp->ar_hrd = htons(ARPHRD_IEEE802);
		arp->ar_pro = htons(ETH_P_IP);
		break;
#endif
	}

	arp->ar_hln = dev->addr_len;//记录设备物理地址长度
	arp->ar_pln = 4;//设备IP地址长度
	arp->ar_op = htons(type);//记录操作类型

	arp_ptr=(unsigned char *)(arp+1);//数据块中用于保存源mac地址处

	memcpy(arp_ptr, src_hw, dev->addr_len);//复制源mac地址
	arp_ptr+=dev->addr_len;//偏移到保存源IP地址处
	memcpy(arp_ptr, &src_ip,4);//复制源ip地址
	arp_ptr+=4;//偏移到目标mac地址处
	if (target_hw != NULL)
		memcpy(arp_ptr, target_hw, dev->addr_len);//复制目标mac地址
	else
		memset(arp_ptr, 0, dev->addr_len);//复制全0,再ARP request报文中，目的MAC地址需要为全0。
	arp_ptr+=dev->addr_len;//偏移到保存目的IP地址处
	memcpy(arp_ptr, &dest_ip, 4);//复制目的ip地址

	return skb;

out:
	kfree_skb(skb);
	return NULL;
}

/*
 *	Send an arp packet.
 */
void arp_xmit(struct sk_buff *skb)
{
	/* Send it off, maybe filter it using firewalling first.  */
	NF_HOOK(NF_ARP, NF_ARP_OUT, skb, NULL, skb->dev, dev_queue_xmit);
}

/*
 *	Create and send an arp packet.
 */
void arp_send(int type, int ptype, __be32 dest_ip,
	      struct net_device *dev, __be32 src_ip,
	      const unsigned char *dest_hw, const unsigned char *src_hw,
	      const unsigned char *target_hw)
{
	struct sk_buff *skb;

	/*
	 *	No arp on this interface.
	 */

	if (dev->flags&IFF_NOARP)
		return;

	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);
	if (skb == NULL) {
		return;
	}

	arp_xmit(skb);//发送arp reply报文
}

/*
 *	Process an arp request.
 */

static int arp_process(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;//报文入设备
	struct in_device *in_dev = in_dev_get(dev);//设备地址信息
	struct arphdr *arp;
	unsigned char *arp_ptr;
	struct rtable *rt;//缓存路由
	unsigned char *sha;
	__be32 sip, tip;
	u16 dev_type = dev->type;//设备类型
	int addr_type;
	struct neighbour *n;
	struct net *net = dev_net(dev);

	/* arp_rcv below verifies the ARP header and verifies the device
	 * is ARP'able.
	 */

	if (in_dev == NULL)
		goto out;

	arp = arp_hdr(skb);//获取arp报文头

	switch (dev_type) {
	default:
		if (arp->ar_pro != htons(ETH_P_IP) ||
		    htons(dev_type) != arp->ar_hrd)
			goto out;
		break;
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802_TR:
	case ARPHRD_FDDI:
	case ARPHRD_IEEE802:
		/*
		 * ETHERNET, Token Ring and Fibre Channel (which are IEEE 802
		 * devices, according to RFC 2625) devices will accept ARP
		 * hardware types of either 1 (Ethernet) or 6 (IEEE 802.2).
		 * This is the case also of FDDI, where the RFC 1390 says that
		 * FDDI devices should accept ARP hardware of (1) Ethernet,
		 * however, to be more robust, we'll accept both 1 (Ethernet)
		 * or 6 (IEEE 802.2)
		 */
		if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
		     arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
		    arp->ar_pro != htons(ETH_P_IP))
			goto out;
		break;
	case ARPHRD_AX25:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_AX25))
			goto out;
		break;
	case ARPHRD_NETROM:
		if (arp->ar_pro != htons(AX25_P_IP) ||
		    arp->ar_hrd != htons(ARPHRD_NETROM))
			goto out;
		break;
	}

	/* Understand only these message types 只处理arp reply和request*/

	if (arp->ar_op != htons(ARPOP_REPLY) &&
	    arp->ar_op != htons(ARPOP_REQUEST))
		goto out;

/*
 *	Extract fields
 */
	arp_ptr= (unsigned char *)(arp+1);//指向数据块中的源 MAC 地址处
	sha	= arp_ptr;//客户端mac地址
	arp_ptr += dev->addr_len;//偏移到源IP位置
	memcpy(&sip, arp_ptr, 4);//拷贝源IP地址
	arp_ptr += 4;//跳过源IP，指向目的MAC地址处
	arp_ptr += dev->addr_len;//跳过目的mac地址，指向目的IP地址处
	memcpy(&tip, arp_ptr, 4);//拷贝目的IP地址
/*
 *	Check for bad requests for 127.x.x.x and requests for multicast
 *	addresses.  If this is one such, delete it.回文和组播地址不处理
 */
	if (ipv4_is_loopback(tip) || ipv4_is_multicast(tip))
		goto out;

/*
 *     Special case: We must set Frame Relay source Q.922 address
 */
	if (dev_type == ARPHRD_DLCI)
		sha = dev->broadcast;

/*
 *  Process entry.  The idea here is we want to send a reply if it is a
 *  request for us or if it is a request for someone else that we hold
 *  a proxy for.  We want to add an entry to our cache if it is a reply
 *  to us or if it is a request for our address.
 *  (The assumption for this last is that if someone is requesting our
 *  address, they are probably intending to talk to us, so it saves time
 *  if we cache their address.  Their address is also probably not in
 *  our cache, since ours is not in their cache.)
 *
 *  Putting this another way, we only care about replies if they are to
 *  us, in which case we add them to the cache.  For requests, we care
 *  about those for us and those for our proxies.  We reply to both,
 *  and in the case of requests for us we add the requester to the arp
 *  cache.
 */

	/* Special case: IPv4 duplicate address detection packet (RFC2131) */
	if (sip == 0) {
		if (arp->ar_op == htons(ARPOP_REQUEST) &&
		    inet_addr_type(net, tip) == RTN_LOCAL &&
		    !arp_ignore(in_dev, sip, tip))
			arp_send(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha,
				 dev->dev_addr, sha);
		goto out;
	}
	//ARP请求报文，请求报文必知道源IP和目标IP，目标MAC未知。此时的skb->rtable一定为空，ip_route_input()查询local路由表，查询local路由表是为了确认sip是否本地IP，例如主机有2张网卡，接在同一个交换机上。从交换机上另外一台主机上发送arp报文到请求网卡1的MAC，此时网卡2也会收到。
	//将构造缓存路由项并赋值到skb->rtable中。
	if (arp->ar_op == htons(ARPOP_REQUEST) &&
	    ip_route_input(skb, tip, sip, 0, dev) == 0) {

		rt = skb->rtable;//缓存路由项
		addr_type = rt->rt_type;//路由类型

		if (addr_type == RTN_LOCAL) {//sip和tip都是本地地址
			n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
			if (n) {
				int dont_send = 0;

				if (!dont_send)
					dont_send |= arp_ignore(in_dev,sip,tip);//查看/proc/sys/net/conf/all/arp_ignore
				if (!dont_send && IN_DEV_ARPFILTER(in_dev))//查看/proc/sys/net/conf/all/arp_filter
					dont_send |= arp_filter(sip,tip,dev);
				if (!dont_send)//发送arp reply
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);

				neigh_release(n);
			}
			goto out;
		} else if (IN_DEV_FORWARD(in_dev)) {//是否开启转发
			    if (addr_type == RTN_UNICAST  && rt->u.dst.dev != dev &&
			     (arp_fwd_proxy(in_dev, rt) || pneigh_lookup(&arp_tbl, net, &tip, dev, 0))) {
				n = neigh_event_ns(&arp_tbl, sha, &sip, dev);
				if (n)
					neigh_release(n);

				if (NEIGH_CB(skb)->flags & LOCALLY_ENQUEUED ||
				    skb->pkt_type == PACKET_HOST || //目的地是本机的arp request报文
				    in_dev->arp_parms->proxy_delay == 0) {
					arp_send(ARPOP_REPLY,ETH_P_ARP,sip,dev,tip,sha,dev->dev_addr,sha);
				} else {
					pneigh_enqueue(&arp_tbl, in_dev->arp_parms, skb);
					in_dev_put(in_dev);
					return 0;
				}
				goto out;
			}
		}
	}

	/* Update our ARP tables 更新本地的arp表，没有就新建一个 neighbour*/

	n = __neigh_lookup(&arp_tbl, &sip, dev, 0);

	if (IPV4_DEVCONF_ALL(dev_net(dev), ARP_ACCEPT)) {
		/* Unsolicited ARP is not accepted by default.
		   It is possible, that this option should be enabled for some
		   devices (strip is candidate)
		 */
		if (n == NULL &&
		    arp->ar_op == htons(ARPOP_REPLY) &&
		    inet_addr_type(net, sip) == RTN_UNICAST)
			n = __neigh_lookup(&arp_tbl, &sip, dev, 1);
	}

	if (n) {
		int state = NUD_REACHABLE;
		int override;

		/* If several different ARP replies follows back-to-back,
		   use the FIRST one. It is possible, if several proxy
		   agents are active. Taking the first reply prevents
		   arp trashing and chooses the fastest router.
		 */
		override = time_after(jiffies, n->updated + n->parms->locktime);

		/* Broadcast replies and request packets
		   do not assert neighbour reachability.
		 */
		if (arp->ar_op != htons(ARPOP_REPLY) ||//如果ARP包不是应答类型
		    skb->pkt_type != PACKET_HOST)//数据包不属于本地类型
			state = NUD_STALE;//设置为过期状态
		neigh_update(n, sha, state, override ? NEIGH_UPDATE_F_OVERRIDE : 0);//更新状态为NUD_REACHABLE
		neigh_release(n);
	}

out:
	if (in_dev)
		in_dev_put(in_dev);
	kfree_skb(skb);
	return 0;
}

static void parp_redo(struct sk_buff *skb)
{
	arp_process(skb);
}


/*
 *	Receive an arp request from the device layer.
 */
//L2收到报文后，会判断MAC头中的TYPE字段来判断属于那种协议，然后调用对应的处理函数。arp_rcv就处理ARP 报文
static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	struct arphdr *arp;//arp头

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	if (!pskb_may_pull(skb, arp_hdr_len(dev)))//判断ARP是否有效
		goto freeskb;

	arp = arp_hdr(skb);//获取ARP头
	if (arp->ar_hln != dev->addr_len || //设备地址长度是否一样
	    dev->flags & IFF_NOARP || //设备是否支持ARP协议
	    skb->pkt_type == PACKET_OTHERHOST || //是否发给其他主机的数据包
	    skb->pkt_type == PACKET_BROADCAST || //广播包
	    skb->pkt_type == PACKET_LOOPBACK || //回环包
	    arp->ar_pln != 4)
		goto freeskb;
	//检查能否共享数据包结构,如果能够共享的话就会通过 skb_clone()克隆一个新的数据包结构包，函数使用这个新的数据包结构
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		goto out_of_mem;
	//设置控制块的时候必须先skb_clone(skb_share_check会执行skb_clone操作)一个skb，然后在skb_clone的skb上设置控制块
	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));
	//netFilter处理，最终调用arp_process
	return NF_HOOK(NF_ARP, NF_ARP_IN, skb, dev, NULL, arp_process);

freeskb:
	kfree_skb(skb);
out_of_mem:
	return 0;
}

/*
 *	User level interface (ioctl)
 */

/*
 *	Set (create) an ARP cache entry.
 */

static int arp_req_set_proxy(struct net *net, struct net_device *dev, int on)
{
	if (dev == NULL) {
		IPV4_DEVCONF_ALL(net, PROXY_ARP) = on;
		return 0;
	}
	if (__in_dev_get_rtnl(dev)) {
		IN_DEV_CONF_SET(__in_dev_get_rtnl(dev), PROXY_ARP, on);
		return 0;
	}
	return -ENXIO;
}

static int arp_req_set_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask && mask != htonl(0xFFFFFFFF))
		return -EINVAL;
	if (!dev && (r->arp_flags & ATF_COM)) {
		dev = dev_getbyhwaddr(net, r->arp_ha.sa_family,
				r->arp_ha.sa_data);
		if (!dev)
			return -ENODEV;
	}
	if (mask) {
		if (pneigh_lookup(&arp_tbl, net, &ip, dev, 1) == NULL)
			return -ENOBUFS;
		return 0;
	}

	return arp_req_set_proxy(net, dev, 1);
}

static int arp_req_set(struct net *net, struct arpreq *r,
		struct net_device * dev)
{
	__be32 ip;
	struct neighbour *neigh;
	int err;

	if (r->arp_flags & ATF_PUBL)
		return arp_req_set_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	if (r->arp_flags & ATF_PERM)
		r->arp_flags |= ATF_COM;
	if (dev == NULL) {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = ip,
							 .tos = RTO_ONLINK } } };
		struct rtable * rt;
		if ((err = ip_route_output_key(net, &rt, &fl)) != 0)
			return err;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	switch (dev->type) {
#ifdef CONFIG_FDDI
	case ARPHRD_FDDI:
		/*
		 * According to RFC 1390, FDDI devices should accept ARP
		 * hardware types of 1 (Ethernet).  However, to be more
		 * robust, we'll accept hardware types of either 1 (Ethernet)
		 * or 6 (IEEE 802.2).
		 */
		if (r->arp_ha.sa_family != ARPHRD_FDDI &&
		    r->arp_ha.sa_family != ARPHRD_ETHER &&
		    r->arp_ha.sa_family != ARPHRD_IEEE802)
			return -EINVAL;
		break;
#endif
	default:
		if (r->arp_ha.sa_family != dev->type)
			return -EINVAL;
		break;
	}

	neigh = __neigh_lookup_errno(&arp_tbl, &ip, dev);
	err = PTR_ERR(neigh);
	if (!IS_ERR(neigh)) {
		unsigned state = NUD_STALE;
		if (r->arp_flags & ATF_PERM)
			state = NUD_PERMANENT;
		err = neigh_update(neigh, (r->arp_flags&ATF_COM) ?
				   r->arp_ha.sa_data : NULL, state,
				   NEIGH_UPDATE_F_OVERRIDE|
				   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
	}
	return err;
}

static unsigned arp_state_to_flags(struct neighbour *neigh)
{
	unsigned flags = 0;
	if (neigh->nud_state&NUD_PERMANENT)
		flags = ATF_PERM|ATF_COM;
	else if (neigh->nud_state&NUD_VALID)
		flags = ATF_COM;
	return flags;
}

/*
 *	Get an ARP cache entry.
 */

static int arp_req_get(struct arpreq *r, struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	struct neighbour *neigh;
	int err = -ENXIO;

	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		read_lock_bh(&neigh->lock);
		memcpy(r->arp_ha.sa_data, neigh->ha, dev->addr_len);
		r->arp_flags = arp_state_to_flags(neigh);
		read_unlock_bh(&neigh->lock);
		r->arp_ha.sa_family = dev->type;
		strlcpy(r->arp_dev, dev->name, sizeof(r->arp_dev));
		neigh_release(neigh);
		err = 0;
	}
	return err;
}

static int arp_req_delete_public(struct net *net, struct arpreq *r,
		struct net_device *dev)
{
	__be32 ip = ((struct sockaddr_in *) &r->arp_pa)->sin_addr.s_addr;
	__be32 mask = ((struct sockaddr_in *)&r->arp_netmask)->sin_addr.s_addr;

	if (mask == htonl(0xFFFFFFFF))
		return pneigh_delete(&arp_tbl, net, &ip, dev);

	if (mask)
		return -EINVAL;

	return arp_req_set_proxy(net, dev, 0);
}

static int arp_req_delete(struct net *net, struct arpreq *r,
		struct net_device * dev)
{
	int err;
	__be32 ip;
	struct neighbour *neigh;

	if (r->arp_flags & ATF_PUBL)
		return arp_req_delete_public(net, r, dev);

	ip = ((struct sockaddr_in *)&r->arp_pa)->sin_addr.s_addr;
	if (dev == NULL) {
		struct flowi fl = { .nl_u = { .ip4_u = { .daddr = ip,
							 .tos = RTO_ONLINK } } };
		struct rtable * rt;
		if ((err = ip_route_output_key(net, &rt, &fl)) != 0)
			return err;
		dev = rt->u.dst.dev;
		ip_rt_put(rt);
		if (!dev)
			return -EINVAL;
	}
	err = -ENXIO;
	neigh = neigh_lookup(&arp_tbl, &ip, dev);
	if (neigh) {
		if (neigh->nud_state&~NUD_NOARP)
			err = neigh_update(neigh, NULL, NUD_FAILED,
					   NEIGH_UPDATE_F_OVERRIDE|
					   NEIGH_UPDATE_F_ADMIN);
		neigh_release(neigh);
	}
	return err;
}

/*
 *	Handle an ARP layer I/O control request.
 */

int arp_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	int err;
	struct arpreq r;
	struct net_device *dev = NULL;

	switch (cmd) {
		case SIOCDARP:
		case SIOCSARP:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
		case SIOCGARP:
			err = copy_from_user(&r, arg, sizeof(struct arpreq));
			if (err)
				return -EFAULT;
			break;
		default:
			return -EINVAL;
	}

	if (r.arp_pa.sa_family != AF_INET)
		return -EPFNOSUPPORT;

	if (!(r.arp_flags & ATF_PUBL) &&
	    (r.arp_flags & (ATF_NETMASK|ATF_DONTPUB)))
		return -EINVAL;
	if (!(r.arp_flags & ATF_NETMASK))
		((struct sockaddr_in *)&r.arp_netmask)->sin_addr.s_addr =
							   htonl(0xFFFFFFFFUL);
	rtnl_lock();
	if (r.arp_dev[0]) {
		err = -ENODEV;
		if ((dev = __dev_get_by_name(net, r.arp_dev)) == NULL)
			goto out;

		/* Mmmm... It is wrong... ARPHRD_NETROM==0 */
		if (!r.arp_ha.sa_family)
			r.arp_ha.sa_family = dev->type;
		err = -EINVAL;
		if ((r.arp_flags & ATF_COM) && r.arp_ha.sa_family != dev->type)
			goto out;
	} else if (cmd == SIOCGARP) {
		err = -ENODEV;
		goto out;
	}

	switch (cmd) {
	case SIOCDARP:
		err = arp_req_delete(net, &r, dev);
		break;
	case SIOCSARP:
		err = arp_req_set(net, &r, dev);
		break;
	case SIOCGARP:
		err = arp_req_get(&r, dev);
		if (!err && copy_to_user(arg, &r, sizeof(r)))
			err = -EFAULT;
		break;
	}
out:
	rtnl_unlock();
	return err;
}

static int arp_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	switch (event) {
	case NETDEV_CHANGEADDR:
		neigh_changeaddr(&arp_tbl, dev);
		rt_cache_flush(0);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block arp_netdev_notifier = {
	.notifier_call = arp_netdev_event,
};

/* Note, that it is not on notifier chain.
   It is necessary, that this routine was called after route cache will be
   flushed.
 */
void arp_ifdown(struct net_device *dev)
{
	neigh_ifdown(&arp_tbl, dev);
}


/*
 *	Called once on startup.
 */

static struct packet_type arp_packet_type = {
	.type =	__constant_htons(ETH_P_ARP),
	.func =	arp_rcv,
};

static int arp_proc_init(void);

void __init arp_init(void)
{
	neigh_table_init(&arp_tbl);//将arp表插入到全局的 neigh_tables中

	dev_add_pack(&arp_packet_type);//将arp协议添加到协议栈中，当收到数据包，分析是arp报文，就会调用arp_packet_type->func->arp_rcv()
	arp_proc_init();//初始化arp proc文件相关
#ifdef CONFIG_SYSCTL
	neigh_sysctl_register(NULL, &arp_tbl.parms, NET_IPV4,
			      NET_IPV4_NEIGH, "ipv4", NULL, NULL);//arp表的sysctl文件，通过sysctl可以查看修改arp_tbl.parms参数。sysctl -N net.ipv4.neigh
#endif
	register_netdevice_notifier(&arp_netdev_notifier);//注册arp_netdev_notifier，当net_device发生改变时，就会调用arp_netdev_event()
}

#ifdef CONFIG_PROC_FS
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)

/* ------------------------------------------------------------------------ */
/*
 *	ax25 -> ASCII conversion
 */
static char *ax2asc2(ax25_address *a, char *buf)
{
	char c, *s;
	int n;

	for (n = 0, s = buf; n < 6; n++) {
		c = (a->ax25_call[n] >> 1) & 0x7F;

		if (c != ' ') *s++ = c;
	}

	*s++ = '-';

	if ((n = ((a->ax25_call[6] >> 1) & 0x0F)) > 9) {
		*s++ = '1';
		n -= 10;
	}

	*s++ = n + '0';
	*s++ = '\0';

	if (*buf == '\0' || *buf == '-')
	   return "*";

	return buf;

}
#endif /* CONFIG_AX25 */

#define HBUFFERLEN 30

static void arp_format_neigh_entry(struct seq_file *seq,
				   struct neighbour *n)
{
	char hbuffer[HBUFFERLEN];
	int k, j;
	char tbuf[16];
	struct net_device *dev = n->dev;
	int hatype = dev->type;

	read_lock(&n->lock);
	/* Convert hardware address to XX:XX:XX:XX ... form. */
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	if (hatype == ARPHRD_AX25 || hatype == ARPHRD_NETROM)
		ax2asc2((ax25_address *)n->ha, hbuffer);
	else {
#endif
	for (k = 0, j = 0; k < HBUFFERLEN - 3 && j < dev->addr_len; j++) {
		hbuffer[k++] = hex_asc_hi(n->ha[j]);
		hbuffer[k++] = hex_asc_lo(n->ha[j]);
		hbuffer[k++] = ':';
	}
	hbuffer[--k] = 0;
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
	}
#endif
	sprintf(tbuf, NIPQUAD_FMT, NIPQUAD(*(u32*)n->primary_key));
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, arp_state_to_flags(n), hbuffer, dev->name);
	read_unlock(&n->lock);
}

static void arp_format_pneigh_entry(struct seq_file *seq,
				    struct pneigh_entry *n)
{
	struct net_device *dev = n->dev;
	int hatype = dev ? dev->type : 0;
	char tbuf[16];

	sprintf(tbuf, NIPQUAD_FMT, NIPQUAD(*(u32*)n->key));
	seq_printf(seq, "%-16s 0x%-10x0x%-10x%s     *        %s\n",
		   tbuf, hatype, ATF_PUBL | ATF_PERM, "00:00:00:00:00:00",
		   dev ? dev->name : "*");
}

static int arp_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "IP address       HW type     Flags       "
			      "HW address            Mask     Device\n");
	} else {
		struct neigh_seq_state *state = seq->private;

		if (state->flags & NEIGH_SEQ_IS_PNEIGH)
			arp_format_pneigh_entry(seq, v);
		else
			arp_format_neigh_entry(seq, v);
	}

	return 0;
}

static void *arp_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* Don't want to confuse "arp -a" w/ magic entries,
	 * so we tell the generic iterator to skip NUD_NOARP.
	 */
	return neigh_seq_start(seq, pos, &arp_tbl, NEIGH_SEQ_SKIP_NOARP);
}

/* ------------------------------------------------------------------------ */

static const struct seq_operations arp_seq_ops = {
	.start  = arp_seq_start,
	.next   = neigh_seq_next,
	.stop   = neigh_seq_stop,
	.show   = arp_seq_show,
};

static int arp_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &arp_seq_ops,
			    sizeof(struct neigh_seq_state));
}

static const struct file_operations arp_seq_fops = {
	.owner		= THIS_MODULE,
	.open           = arp_seq_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release	= seq_release_net,
};


static int __net_init arp_net_init(struct net *net)
{
	if (!proc_net_fops_create(net, "arp", S_IRUGO, &arp_seq_fops))//在/proc/{net}/arp/下创建arp文件
		return -ENOMEM;
	return 0;
}

static void __net_exit arp_net_exit(struct net *net)
{
	proc_net_remove(net, "arp");
}

static struct pernet_operations arp_net_ops = {
	.init = arp_net_init,
	.exit = arp_net_exit,
};

static int __init arp_proc_init(void)
{
	return register_pernet_subsys(&arp_net_ops);
}

#else /* CONFIG_PROC_FS */

static int __init arp_proc_init(void)
{
	return 0;
}

#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(arp_broken_ops);
EXPORT_SYMBOL(arp_find);
EXPORT_SYMBOL(arp_create);
EXPORT_SYMBOL(arp_xmit);
EXPORT_SYMBOL(arp_send);
EXPORT_SYMBOL(arp_tbl);

#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
EXPORT_SYMBOL(clip_tbl_hook);
#endif
