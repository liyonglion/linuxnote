/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		ROUTE - implementation of the IP router.
 *
 * Version:	$Id: route.c,v 1.103 2002/01/12 07:44:09 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Linus Torvalds, <Linus.Torvalds@helsinki.fi>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Fixes:
 *		Alan Cox	:	Verify area fixes.
 *		Alan Cox	:	cli() protects routing changes
 *		Rui Oliveira	:	ICMP routing table updates
 *		(rco@di.uminho.pt)	Routing table insertion and update
 *		Linus Torvalds	:	Rewrote bits to be sensible
 *		Alan Cox	:	Added BSD route gw semantics
 *		Alan Cox	:	Super /proc >4K
 *		Alan Cox	:	MTU in route table
 *		Alan Cox	: 	MSS actually. Also added the window
 *					clamper.
 *		Sam Lantinga	:	Fixed route matching in rt_del()
 *		Alan Cox	:	Routing cache support.
 *		Alan Cox	:	Removed compatibility cruft.
 *		Alan Cox	:	RTF_REJECT support.
 *		Alan Cox	:	TCP irtt support.
 *		Jonathan Naylor	:	Added Metric support.
 *	Miquel van Smoorenburg	:	BSD API fixes.
 *	Miquel van Smoorenburg	:	Metrics.
 *		Alan Cox	:	Use __u32 properly
 *		Alan Cox	:	Aligned routing errors more closely with BSD
 *					our system is still very different.
 *		Alan Cox	:	Faster /proc handling
 *	Alexey Kuznetsov	:	Massive rework to support tree based routing,
 *					routing caches and better behaviour.
 *
 *		Olaf Erb	:	irtt wasn't being copied right.
 *		Bjorn Ekwall	:	Kerneld route support.
 *		Alan Cox	:	Multicast fixed (I hope)
 * 		Pavel Krauz	:	Limited broadcast fixed
 *		Mike McLagan	:	Routing by source
 *	Alexey Kuznetsov	:	End of old history. Split to fib.c and
 *					route.c and rewritten from scratch.
 *		Andi Kleen	:	Load-limit warning messages.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *	Vitaly E. Lavrov	:	Race condition in ip_route_input_slow.
 *	Tobias Ringstrom	:	Uninitialized res.type in ip_route_output_slow.
 *	Vladimir V. Ivanov	:	IP rule info (flowid) is really useful.
 *		Marc Boucher	:	routing by fwmark
 *	Robert Olsson		:	Added rt_cache statistics
 *	Arnaldo C. Melo		:	Convert proc stuff to seq_file
 *	Eric Dumazet		:	hashed spinlocks and rt_check_expire() fixes.
 * 	Ilia Sotnikov		:	Ignore TOS on PMTUD and Redirect
 * 	Ilia Sotnikov		:	Removed TOS from hash calculations
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/times.h>
#include <net/dst.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/netevent.h>
#include <net/rtnetlink.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#define RT_FL_TOS(oldflp) \
    ((u32)(oldflp->fl4_tos & (IPTOS_RT_MASK | RTO_ONLINK)))

#define IP_MAX_MTU	0xFFF0

#define RT_GC_TIMEOUT (300*HZ)

static int ip_rt_max_size;
static int ip_rt_gc_timeout __read_mostly	= RT_GC_TIMEOUT;
static int ip_rt_gc_interval __read_mostly	= 60 * HZ;
static int ip_rt_gc_min_interval __read_mostly	= HZ / 2;
static int ip_rt_redirect_number __read_mostly	= 9;
static int ip_rt_redirect_load __read_mostly	= HZ / 50;
static int ip_rt_redirect_silence __read_mostly	= ((HZ / 50) << (9 + 1));
static int ip_rt_error_cost __read_mostly	= HZ;
static int ip_rt_error_burst __read_mostly	= 5 * HZ;
static int ip_rt_gc_elasticity __read_mostly	= 8;
static int ip_rt_mtu_expires __read_mostly	= 10 * 60 * HZ;
static int ip_rt_min_pmtu __read_mostly		= 512 + 20 + 20;
static int ip_rt_min_advmss __read_mostly	= 256;
static int ip_rt_secret_interval __read_mostly	= 10 * 60 * HZ;

static void rt_worker_func(struct work_struct *work);
static DECLARE_DELAYED_WORK(expires_work, rt_worker_func);
static struct timer_list rt_secret_timer;

/*
 *	Interface to generic destination cache.
 */

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie);
static void		 ipv4_dst_destroy(struct dst_entry *dst);
static void		 ipv4_dst_ifdown(struct dst_entry *dst,
					 struct net_device *dev, int how);
static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst);
static void		 ipv4_link_failure(struct sk_buff *skb);
static void		 ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu);
static int rt_garbage_collect(struct dst_ops *ops);


static struct dst_ops ipv4_dst_ops = {
	.family =		AF_INET,
	.protocol =		__constant_htons(ETH_P_IP),
	.gc =			rt_garbage_collect,
	.check =		ipv4_dst_check,
	.destroy =		ipv4_dst_destroy,
	.ifdown =		ipv4_dst_ifdown,
	.negative_advice =	ipv4_negative_advice,
	.link_failure =		ipv4_link_failure,
	.update_pmtu =		ip_rt_update_pmtu,
	.local_out =		__ip_local_out,
	.entry_size =		sizeof(struct rtable),
	.entries =		ATOMIC_INIT(0),
};

#define ECN_OR_COST(class)	TC_PRIO_##class

const __u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};


/*
 * Route cache.
 */

/* The locking scheme is rather straight forward:
 *
 * 1) Read-Copy Update protects the buckets of the central route hash.
 * 2) Only writers remove entries, and they hold the lock
 *    as they look at rtable reference counts.
 * 3) Only readers acquire references to rtable entries,
 *    they do so with atomic increments and with the
 *    lock held.
 */

struct rt_hash_bucket {
	struct rtable	*chain;
};
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK) || \
	defined(CONFIG_PROVE_LOCKING)
/*
 * Instead of using one spinlock for each rt_hash_bucket, we use a table of spinlocks
 * The size of this table is a power of two and depends on the number of CPUS.
 * (on lockdep we have a quite big spinlock_t, so keep the size down there)
 */
#ifdef CONFIG_LOCKDEP
# define RT_HASH_LOCK_SZ	256
#else
# if NR_CPUS >= 32
#  define RT_HASH_LOCK_SZ	4096
# elif NR_CPUS >= 16
#  define RT_HASH_LOCK_SZ	2048
# elif NR_CPUS >= 8
#  define RT_HASH_LOCK_SZ	1024
# elif NR_CPUS >= 4
#  define RT_HASH_LOCK_SZ	512
# else
#  define RT_HASH_LOCK_SZ	256
# endif
#endif

static spinlock_t	*rt_hash_locks;
# define rt_hash_lock_addr(slot) &rt_hash_locks[(slot) & (RT_HASH_LOCK_SZ - 1)]

static __init void rt_hash_lock_init(void)
{
	int i;

	rt_hash_locks = kmalloc(sizeof(spinlock_t) * RT_HASH_LOCK_SZ,
			GFP_KERNEL);
	if (!rt_hash_locks)
		panic("IP: failed to allocate rt_hash_locks\n");

	for (i = 0; i < RT_HASH_LOCK_SZ; i++)
		spin_lock_init(&rt_hash_locks[i]);
}
#else
# define rt_hash_lock_addr(slot) NULL

static inline void rt_hash_lock_init(void)
{
}
#endif
//路由缓存hash表
static struct rt_hash_bucket 	*rt_hash_table __read_mostly;
//路由hash桶的数量
static unsigned			rt_hash_mask __read_mostly;
static unsigned int		rt_hash_log  __read_mostly;
static atomic_t			rt_genid __read_mostly;//路由随机数

static DEFINE_PER_CPU(struct rt_cache_stat, rt_cache_stat);
#define RT_CACHE_STAT_INC(field) \
	(__raw_get_cpu_var(rt_cache_stat).field++)

static inline unsigned int rt_hash(__be32 daddr, __be32 saddr, int idx)
{
	return jhash_3words((__force u32)(__be32)(daddr),
			    (__force u32)(__be32)(saddr),
			    idx, atomic_read(&rt_genid))
		& rt_hash_mask;
}

#ifdef CONFIG_PROC_FS
struct rt_cache_iter_state {
	struct seq_net_private p;
	int bucket;
	int genid;
};

static struct rtable *rt_cache_get_first(struct seq_file *seq)
{
	struct rt_cache_iter_state *st = seq->private;
	struct rtable *r = NULL;

	for (st->bucket = rt_hash_mask; st->bucket >= 0; --st->bucket) {
		rcu_read_lock_bh();
		r = rcu_dereference(rt_hash_table[st->bucket].chain);
		while (r) {
			if (dev_net(r->u.dst.dev) == seq_file_net(seq) &&
			    r->rt_genid == st->genid)
				return r;
			r = rcu_dereference(r->u.dst.rt_next);
		}
		rcu_read_unlock_bh();
	}
	return r;
}

static struct rtable *__rt_cache_get_next(struct seq_file *seq,
					  struct rtable *r)
{
	struct rt_cache_iter_state *st = seq->private;
	r = r->u.dst.rt_next;
	while (!r) {
		rcu_read_unlock_bh();
		if (--st->bucket < 0)
			break;
		rcu_read_lock_bh();
		r = rt_hash_table[st->bucket].chain;
	}
	return rcu_dereference(r);
}

static struct rtable *rt_cache_get_next(struct seq_file *seq,
					struct rtable *r)
{
	struct rt_cache_iter_state *st = seq->private;
	while ((r = __rt_cache_get_next(seq, r)) != NULL) {
		if (dev_net(r->u.dst.dev) != seq_file_net(seq))
			continue;
		if (r->rt_genid == st->genid)
			break;
	}
	return r;
}

static struct rtable *rt_cache_get_idx(struct seq_file *seq, loff_t pos)
{
	struct rtable *r = rt_cache_get_first(seq);

	if (r)
		while (pos && (r = rt_cache_get_next(seq, r)))
			--pos;
	return pos ? NULL : r;
}

static void *rt_cache_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct rt_cache_iter_state *st = seq->private;
	if (*pos)
		return rt_cache_get_idx(seq, *pos - 1);
	st->genid = atomic_read(&rt_genid);
	return SEQ_START_TOKEN;
}

static void *rt_cache_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct rtable *r;

	if (v == SEQ_START_TOKEN)
		r = rt_cache_get_first(seq);
	else
		r = rt_cache_get_next(seq, v);
	++*pos;
	return r;
}

static void rt_cache_seq_stop(struct seq_file *seq, void *v)
{
	if (v && v != SEQ_START_TOKEN)
		rcu_read_unlock_bh();
}

static int rt_cache_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   "Iface\tDestination\tGateway \tFlags\t\tRefCnt\tUse\t"
			   "Metric\tSource\t\tMTU\tWindow\tIRTT\tTOS\tHHRef\t"
			   "HHUptod\tSpecDst");
	else {
		struct rtable *r = v;
		int len;

		seq_printf(seq, "%s\t%08lX\t%08lX\t%8X\t%d\t%u\t%d\t"
			      "%08lX\t%d\t%u\t%u\t%02X\t%d\t%1d\t%08X%n",
			r->u.dst.dev ? r->u.dst.dev->name : "*",
			(unsigned long)r->rt_dst, (unsigned long)r->rt_gateway,
			r->rt_flags, atomic_read(&r->u.dst.__refcnt),
			r->u.dst.__use, 0, (unsigned long)r->rt_src,
			(dst_metric(&r->u.dst, RTAX_ADVMSS) ?
			     (int)dst_metric(&r->u.dst, RTAX_ADVMSS) + 40 : 0),
			dst_metric(&r->u.dst, RTAX_WINDOW),
			(int)((dst_metric(&r->u.dst, RTAX_RTT) >> 3) +
			      dst_metric(&r->u.dst, RTAX_RTTVAR)),
			r->fl.fl4_tos,
			r->u.dst.hh ? atomic_read(&r->u.dst.hh->hh_refcnt) : -1,
			r->u.dst.hh ? (r->u.dst.hh->hh_output ==
				       dev_queue_xmit) : 0,
			r->rt_spec_dst, &len);

		seq_printf(seq, "%*s\n", 127 - len, "");
	}
	return 0;
}

static const struct seq_operations rt_cache_seq_ops = {
	.start  = rt_cache_seq_start,
	.next   = rt_cache_seq_next,
	.stop   = rt_cache_seq_stop,
	.show   = rt_cache_seq_show,
};

static int rt_cache_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &rt_cache_seq_ops,
			sizeof(struct rt_cache_iter_state));
}

static const struct file_operations rt_cache_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cache_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release_net,
};


static void *rt_cpu_seq_start(struct seq_file *seq, loff_t *pos)
{
	int cpu;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	for (cpu = *pos-1; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return &per_cpu(rt_cache_stat, cpu);
	}
	return NULL;
}

static void *rt_cpu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int cpu;

	for (cpu = *pos; cpu < NR_CPUS; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*pos = cpu+1;
		return &per_cpu(rt_cache_stat, cpu);
	}
	return NULL;

}

static void rt_cpu_seq_stop(struct seq_file *seq, void *v)
{

}

static int rt_cpu_seq_show(struct seq_file *seq, void *v)
{
	struct rt_cache_stat *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "entries  in_hit in_slow_tot in_slow_mc in_no_route in_brd in_martian_dst in_martian_src  out_hit out_slow_tot out_slow_mc  gc_total gc_ignored gc_goal_miss gc_dst_overflow in_hlist_search out_hlist_search\n");
		return 0;
	}

	seq_printf(seq,"%08x  %08x %08x %08x %08x %08x %08x %08x "
		   " %08x %08x %08x %08x %08x %08x %08x %08x %08x \n",
		   atomic_read(&ipv4_dst_ops.entries),
		   st->in_hit,
		   st->in_slow_tot,
		   st->in_slow_mc,
		   st->in_no_route,
		   st->in_brd,
		   st->in_martian_dst,
		   st->in_martian_src,

		   st->out_hit,
		   st->out_slow_tot,
		   st->out_slow_mc,

		   st->gc_total,
		   st->gc_ignored,
		   st->gc_goal_miss,
		   st->gc_dst_overflow,
		   st->in_hlist_search,
		   st->out_hlist_search
		);
	return 0;
}

static const struct seq_operations rt_cpu_seq_ops = {
	.start  = rt_cpu_seq_start,
	.next   = rt_cpu_seq_next,
	.stop   = rt_cpu_seq_stop,
	.show   = rt_cpu_seq_show,
};


static int rt_cpu_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &rt_cpu_seq_ops);
}

static const struct file_operations rt_cpu_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = rt_cpu_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

#ifdef CONFIG_NET_CLS_ROUTE
static int ip_rt_acct_read(char *buffer, char **start, off_t offset,
			   int length, int *eof, void *data)
{
	unsigned int i;

	if ((offset & 3) || (length & 3))
		return -EIO;

	if (offset >= sizeof(struct ip_rt_acct) * 256) {
		*eof = 1;
		return 0;
	}

	if (offset + length >= sizeof(struct ip_rt_acct) * 256) {
		length = sizeof(struct ip_rt_acct) * 256 - offset;
		*eof = 1;
	}

	offset /= sizeof(u32);

	if (length > 0) {
		u32 *dst = (u32 *) buffer;

		*start = buffer;
		memset(dst, 0, length);

		for_each_possible_cpu(i) {
			unsigned int j;
			u32 *src;

			src = ((u32 *) per_cpu_ptr(ip_rt_acct, i)) + offset;
			for (j = 0; j < length/4; j++)
				dst[j] += src[j];
		}
	}
	return length;
}
#endif

static int __net_init ip_rt_do_proc_init(struct net *net)
{
	struct proc_dir_entry *pde;

	pde = proc_net_fops_create(net, "rt_cache", S_IRUGO,
			&rt_cache_seq_fops);
	if (!pde)
		goto err1;

	pde = proc_create("rt_cache", S_IRUGO,
			  net->proc_net_stat, &rt_cpu_seq_fops);
	if (!pde)
		goto err2;

#ifdef CONFIG_NET_CLS_ROUTE
	pde = create_proc_read_entry("rt_acct", 0, net->proc_net,
			ip_rt_acct_read, NULL);
	if (!pde)
		goto err3;
#endif
	return 0;

#ifdef CONFIG_NET_CLS_ROUTE
err3:
	remove_proc_entry("rt_cache", net->proc_net_stat);
#endif
err2:
	remove_proc_entry("rt_cache", net->proc_net);
err1:
	return -ENOMEM;
}

static void __net_exit ip_rt_do_proc_exit(struct net *net)
{
	remove_proc_entry("rt_cache", net->proc_net_stat);
	remove_proc_entry("rt_cache", net->proc_net);
	remove_proc_entry("rt_acct", net->proc_net);
}

static struct pernet_operations ip_rt_proc_ops __net_initdata =  {
	.init = ip_rt_do_proc_init,
	.exit = ip_rt_do_proc_exit,
};

static int __init ip_rt_proc_init(void)
{
	return register_pernet_subsys(&ip_rt_proc_ops);
}

#else
static inline int ip_rt_proc_init(void)
{
	return 0;
}
#endif /* CONFIG_PROC_FS */

static inline void rt_free(struct rtable *rt)
{
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static inline void rt_drop(struct rtable *rt)
{
	ip_rt_put(rt);
	call_rcu_bh(&rt->u.dst.rcu_head, dst_rcu_free);
}

static inline int rt_fast_clean(struct rtable *rth)
{
	/* Kill broadcast/multicast entries very aggresively, if they
	   collide in hash table with more useful entries */
	return (rth->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)) &&
		rth->fl.iif && rth->u.dst.rt_next;
}

static inline int rt_valuable(struct rtable *rth)
{
	return (rth->rt_flags & (RTCF_REDIRECTED | RTCF_NOTIFY)) ||
		rth->u.dst.expires;
}

static int rt_may_expire(struct rtable *rth, unsigned long tmo1, unsigned long tmo2)
{
	unsigned long age;
	int ret = 0;

	if (atomic_read(&rth->u.dst.__refcnt))
		goto out;

	ret = 1;
	if (rth->u.dst.expires &&
	    time_after_eq(jiffies, rth->u.dst.expires))
		goto out;

	age = jiffies - rth->u.dst.lastuse;
	ret = 0;
	if ((age <= tmo1 && !rt_fast_clean(rth)) ||
	    (age <= tmo2 && rt_valuable(rth)))
		goto out;
	ret = 1;
out:	return ret;
}

/* Bits of score are:
 * 31: very valuable
 * 30: not quite useless
 * 29..0: usage counter
 */
static inline u32 rt_score(struct rtable *rt)
{
	u32 score = jiffies - rt->u.dst.lastuse;

	score = ~score & ~(3<<30);

	if (rt_valuable(rt))
		score |= (1<<31);

	if (!rt->fl.iif ||
	    !(rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST|RTCF_LOCAL)))
		score |= (1<<30);

	return score;
}

static inline int compare_keys(struct flowi *fl1, struct flowi *fl2)
{
	return ((__force u32)((fl1->nl_u.ip4_u.daddr ^ fl2->nl_u.ip4_u.daddr) |
		(fl1->nl_u.ip4_u.saddr ^ fl2->nl_u.ip4_u.saddr)) |
		(fl1->mark ^ fl2->mark) |
		(*(u16 *)&fl1->nl_u.ip4_u.tos ^
		 *(u16 *)&fl2->nl_u.ip4_u.tos) |
		(fl1->oif ^ fl2->oif) |
		(fl1->iif ^ fl2->iif)) == 0;
}

static inline int compare_netns(struct rtable *rt1, struct rtable *rt2)
{
	return dev_net(rt1->u.dst.dev) == dev_net(rt2->u.dst.dev);
}

/*
 * Perform a full scan of hash table and free all entries.
 * Can be called by a softirq or a process.
 * In the later case, we want to be reschedule if necessary
 */
static void rt_do_flush(int process_context)
{
	unsigned int i;
	struct rtable *rth, *next;

	for (i = 0; i <= rt_hash_mask; i++) {
		if (process_context && need_resched())
			cond_resched();
		rth = rt_hash_table[i].chain;
		if (!rth)
			continue;

		spin_lock_bh(rt_hash_lock_addr(i));
		rth = rt_hash_table[i].chain;
		rt_hash_table[i].chain = NULL;
		spin_unlock_bh(rt_hash_lock_addr(i));

		for (; rth; rth = next) {
			next = rth->u.dst.rt_next;
			rt_free(rth);
		}
	}
}

static void rt_check_expire(void)
{
	static unsigned int rover;
	unsigned int i = rover, goal;
	struct rtable *rth, **rthp;
	u64 mult;

	mult = ((u64)ip_rt_gc_interval) << rt_hash_log;
	if (ip_rt_gc_timeout > 1)
		do_div(mult, ip_rt_gc_timeout);
	goal = (unsigned int)mult;
	if (goal > rt_hash_mask)
		goal = rt_hash_mask + 1;
	for (; goal > 0; goal--) {
		unsigned long tmo = ip_rt_gc_timeout;

		i = (i + 1) & rt_hash_mask;
		rthp = &rt_hash_table[i].chain;

		if (need_resched())
			cond_resched();

		if (*rthp == NULL)
			continue;
		spin_lock_bh(rt_hash_lock_addr(i));
		while ((rth = *rthp) != NULL) {
			if (rth->rt_genid != atomic_read(&rt_genid)) {
				*rthp = rth->u.dst.rt_next;
				rt_free(rth);
				continue;
			}
			if (rth->u.dst.expires) {
				/* Entry is expired even if it is in use */
				if (time_before_eq(jiffies, rth->u.dst.expires)) {
					tmo >>= 1;
					rthp = &rth->u.dst.rt_next;
					continue;
				}
			} else if (!rt_may_expire(rth, tmo, ip_rt_gc_timeout)) {
				tmo >>= 1;
				rthp = &rth->u.dst.rt_next;
				continue;
			}

			/* Cleanup aged off entries. */
			*rthp = rth->u.dst.rt_next;
			rt_free(rth);
		}
		spin_unlock_bh(rt_hash_lock_addr(i));
	}
	rover = i;
}

/*
 * rt_worker_func() is run in process context.
 * we call rt_check_expire() to scan part of the hash table
 */
static void rt_worker_func(struct work_struct *work)
{
	rt_check_expire();
	schedule_delayed_work(&expires_work, ip_rt_gc_interval);
}

/*
 * Pertubation of rt_genid by a small quantity [1..256]
 * Using 8 bits of shuffling ensure we can call rt_cache_invalidate()
 * many times (2^24) without giving recent rt_genid.
 * Jenkins hash is strong enough that litle changes of rt_genid are OK.
 */
static void rt_cache_invalidate(void)
{
	unsigned char shuffle;

	get_random_bytes(&shuffle, sizeof(shuffle));
	atomic_add(shuffle + 1U, &rt_genid);
}

/*
 * delay < 0  : invalidate cache (fast : entries will be deleted later)
 * delay >= 0 : invalidate & flush cache (can be long)
 */
void rt_cache_flush(int delay)
{
	rt_cache_invalidate();
	if (delay >= 0)
		rt_do_flush(!in_softirq());
}

/*
 * We change rt_genid and let gc do the cleanup
 */
static void rt_secret_rebuild(unsigned long dummy)
{
	rt_cache_invalidate();
	mod_timer(&rt_secret_timer, jiffies + ip_rt_secret_interval);
}

/*
   Short description of GC goals.

   We want to build algorithm, which will keep routing cache
   at some equilibrium point, when number of aged off entries
   is kept approximately equal to newly generated ones.

   Current expiration strength is variable "expire".
   We try to adjust it dynamically, so that if networking
   is idle expires is large enough to keep enough of warm entries,
   and when load increases it reduces to limit cache size.
 */

static int rt_garbage_collect(struct dst_ops *ops)
{
	static unsigned long expire = RT_GC_TIMEOUT;
	static unsigned long last_gc;
	static int rover;
	static int equilibrium;
	struct rtable *rth, **rthp;
	unsigned long now = jiffies;
	int goal;

	/*
	 * Garbage collection is pretty expensive,
	 * do not make it too frequently.
	 */

	RT_CACHE_STAT_INC(gc_total);

	if (now - last_gc < ip_rt_gc_min_interval &&
	    atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size) {
		RT_CACHE_STAT_INC(gc_ignored);
		goto out;
	}

	/* Calculate number of entries, which we want to expire now. */
	goal = atomic_read(&ipv4_dst_ops.entries) -
		(ip_rt_gc_elasticity << rt_hash_log);
	if (goal <= 0) {
		if (equilibrium < ipv4_dst_ops.gc_thresh)
			equilibrium = ipv4_dst_ops.gc_thresh;
		goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		if (goal > 0) {
			equilibrium += min_t(unsigned int, goal >> 1, rt_hash_mask + 1);
			goal = atomic_read(&ipv4_dst_ops.entries) - equilibrium;
		}
	} else {
		/* We are in dangerous area. Try to reduce cache really
		 * aggressively.
		 */
		goal = max_t(unsigned int, goal >> 1, rt_hash_mask + 1);
		equilibrium = atomic_read(&ipv4_dst_ops.entries) - goal;
	}

	if (now - last_gc >= ip_rt_gc_min_interval)
		last_gc = now;

	if (goal <= 0) {
		equilibrium += goal;
		goto work_done;
	}

	do {
		int i, k;

		for (i = rt_hash_mask, k = rover; i >= 0; i--) {
			unsigned long tmo = expire;

			k = (k + 1) & rt_hash_mask;
			rthp = &rt_hash_table[k].chain;
			spin_lock_bh(rt_hash_lock_addr(k));
			while ((rth = *rthp) != NULL) {
				if (rth->rt_genid == atomic_read(&rt_genid) &&
					!rt_may_expire(rth, tmo, expire)) {
					tmo >>= 1;
					rthp = &rth->u.dst.rt_next;
					continue;
				}
				*rthp = rth->u.dst.rt_next;
				rt_free(rth);
				goal--;
			}
			spin_unlock_bh(rt_hash_lock_addr(k));
			if (goal <= 0)
				break;
		}
		rover = k;

		if (goal <= 0)
			goto work_done;

		/* Goal is not achieved. We stop process if:

		   - if expire reduced to zero. Otherwise, expire is halfed.
		   - if table is not full.
		   - if we are called from interrupt.
		   - jiffies check is just fallback/debug loop breaker.
		     We will not spin here for long time in any case.
		 */

		RT_CACHE_STAT_INC(gc_goal_miss);

		if (expire == 0)
			break;

		expire >>= 1;
#if RT_CACHE_DEBUG >= 2
		printk(KERN_DEBUG "expire>> %u %d %d %d\n", expire,
				atomic_read(&ipv4_dst_ops.entries), goal, i);
#endif

		if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
			goto out;
	} while (!in_softirq() && time_before_eq(jiffies, now));

	if (atomic_read(&ipv4_dst_ops.entries) < ip_rt_max_size)
		goto out;
	if (net_ratelimit())
		printk(KERN_WARNING "dst cache overflow\n");
	RT_CACHE_STAT_INC(gc_dst_overflow);
	return 1;

work_done:
	expire += ip_rt_gc_min_interval;
	if (expire > ip_rt_gc_timeout ||
	    atomic_read(&ipv4_dst_ops.entries) < ipv4_dst_ops.gc_thresh)
		expire = ip_rt_gc_timeout;
#if RT_CACHE_DEBUG >= 2
	printk(KERN_DEBUG "expire++ %u %d %d %d\n", expire,
			atomic_read(&ipv4_dst_ops.entries), goal, rover);
#endif
out:	return 0;
}
/*
1. 查找该路由缓存是否已经在路由缓存的hash链表中，若已存在，则更新使用时间，并将该缓存项放在hash链表的链首（放入链首，因为它很快就会使用到），程序返回
2. 在遍历hash表的时候，对于使用计数为0的缓存项，计算其score值，score值最小的值则有可能被释放内存(当chain_length > ip_rt_gc_elasticity时，即会释放该缓存占用的内存)
3. 调用arp_bind_neighbour进行路由缓存项与邻居项的绑定操作。
4. 将该路由缓存项放在hash链的链首。
*/
static int rt_intern_hash(unsigned hash, struct rtable *rt, struct rtable **rp)
{
	struct rtable	*rth, **rthp;
	unsigned long	now;
	struct rtable *cand, **candp;
	u32 		min_score;
	int		chain_length;
	int attempts = !in_softirq();

restart:
	chain_length = 0;
	min_score = ~(u32)0;
	cand = NULL;
	candp = NULL;
	now = jiffies;
	/*根据值hash，找到rt_hash_table链表中相应的*/
	rthp = &rt_hash_table[hash].chain;
	/*调用相应hash表对应的自旋锁，执行上锁操作*/
	spin_lock_bh(rt_hash_lock_addr(hash));
	while ((rth = *rthp) != NULL) {
		if (rth->rt_genid != atomic_read(&rt_genid)) {
			*rthp = rth->u.dst.rt_next;
			rt_free(rth);
			continue;
		}
		/*路由键值内容是否相同，是否同属一个网络空间，如果相同就说明队列中已经存在相同的路由表结构，把它移动到队列的最前端*/
		if (compare_keys(&rth->fl, &rt->fl) && compare_netns(rth, rt)) {//判断两个路由是否相同
			/* Put it first */
			*rthp = rth->u.dst.rt_next;//放入链头
			/*
			 * Since lookup is lockfree, the deletion
			 * must be visible to another weakly ordered CPU before
			 * the insertion at the start of the hash chain.
			 */
			rcu_assign_pointer(rth->u.dst.rt_next,
					   rt_hash_table[hash].chain);//将当前路由插入到链表头
			/*
			 * Since lookup is lockfree, the update writes
			 * must be ordered for consistency on SMP.
			 */
			rcu_assign_pointer(rt_hash_table[hash].chain, rth);//更新链表头指针

			dst_use(&rth->u.dst, now);
			spin_unlock_bh(rt_hash_lock_addr(hash));

			rt_drop(rt);
			*rp = rth;
			return 0;
		}

		if (!atomic_read(&rth->u.dst.__refcnt)) {//如果rth的引用计数为0，表示rth已经失效，需要删除
			u32 score = rt_score(rth);//计算rth的分数

			if (score <= min_score) {//如果rth的分数小于min_score，表示rth将被释放
				cand = rth;
				candp = rthp;
				min_score = score;
			}
		}

		chain_length++;

		rthp = &rth->u.dst.rt_next;
	}

	if (cand) {
		/* ip_rt_gc_elasticity used to be average length of chain
		 * length, when exceeded gc becomes really aggressive.
		 *
		 * The second limit is less certain. At the moment it allows
		 * only 2 entries per bucket. We will see.
		 */
		if (chain_length > ip_rt_gc_elasticity) {
			*candp = cand->u.dst.rt_next;
			rt_free(cand);
		}
	}

	/* Try to bind route to arp only if it is output
	   route or unicast forwarding path.
	 */
	if (rt->rt_type == RTN_UNICAST || rt->fl.iif == 0) {//单播类型或者没有指定入接口，则需要绑定arp
		int err = arp_bind_neighbour(&rt->u.dst);//绑定arp
		if (err) {//出现错误
			spin_unlock_bh(rt_hash_lock_addr(hash));

			if (err != -ENOBUFS) {
				rt_drop(rt);
				return err;
			}

			/* Neighbour tables are full and nothing
			   can be released. Try to shrink route cache,
			   it is most likely it holds some neighbour records.
			 */
			if (attempts-- > 0) {
				int saved_elasticity = ip_rt_gc_elasticity;
				int saved_int = ip_rt_gc_min_interval;
				ip_rt_gc_elasticity	= 1;
				ip_rt_gc_min_interval	= 0;
				rt_garbage_collect(&ipv4_dst_ops);
				ip_rt_gc_min_interval	= saved_int;
				ip_rt_gc_elasticity	= saved_elasticity;
				goto restart;
			}

			if (net_ratelimit())
				printk(KERN_WARNING "Neighbour table overflow.\n");
			rt_drop(rt);
			return -ENOBUFS;
		}
	}
	//将该路由缓存项放在hash链的链首。
	rt->u.dst.rt_next = rt_hash_table[hash].chain;
#if RT_CACHE_DEBUG >= 2
	if (rt->u.dst.rt_next) {
		struct rtable *trt;
		printk(KERN_DEBUG "rt_cache @%02x: " NIPQUAD_FMT, hash,
		       NIPQUAD(rt->rt_dst));
		for (trt = rt->u.dst.rt_next; trt; trt = trt->u.dst.rt_next)
			printk(" . " NIPQUAD_FMT, NIPQUAD(trt->rt_dst));
		printk("\n");
	}
#endif
	rt_hash_table[hash].chain = rt;
	spin_unlock_bh(rt_hash_lock_addr(hash));
	*rp = rt;
	return 0;
}

void rt_bind_peer(struct rtable *rt, int create)
{
	static DEFINE_SPINLOCK(rt_peer_lock);
	struct inet_peer *peer;

	peer = inet_getpeer(rt->rt_dst, create);

	spin_lock_bh(&rt_peer_lock);
	if (rt->peer == NULL) {
		rt->peer = peer;
		peer = NULL;
	}
	spin_unlock_bh(&rt_peer_lock);
	if (peer)
		inet_putpeer(peer);
}

/*
 * Peer allocation may fail only in serious out-of-memory conditions.  However
 * we still can generate some output.
 * Random ID selection looks a bit dangerous because we have no chances to
 * select ID being unique in a reasonable period of time.
 * But broken packet identifier may be better than no packet at all.
 */
static void ip_select_fb_ident(struct iphdr *iph)
{
	static DEFINE_SPINLOCK(ip_fb_id_lock);
	static u32 ip_fallback_id;
	u32 salt;

	spin_lock_bh(&ip_fb_id_lock);
	salt = secure_ip_id((__force __be32)ip_fallback_id ^ iph->daddr);
	iph->id = htons(salt & 0xFFFF);
	ip_fallback_id = salt;
	spin_unlock_bh(&ip_fb_id_lock);
}

void __ip_select_ident(struct iphdr *iph, struct dst_entry *dst, int more)
{
	struct rtable *rt = (struct rtable *) dst;

	if (rt) {
		if (rt->peer == NULL)
			rt_bind_peer(rt, 1);

		/* If peer is attached to destination, it is never detached,
		   so that we need not to grab a lock to dereference it.
		 */
		if (rt->peer) {
			iph->id = htons(inet_getid(rt->peer, more));
			return;
		}
	} else
		printk(KERN_DEBUG "rt_bind_peer(0) @%p\n",
		       __builtin_return_address(0));

	ip_select_fb_ident(iph);
}

static void rt_del(unsigned hash, struct rtable *rt)
{
	struct rtable **rthp, *aux;

	rthp = &rt_hash_table[hash].chain;
	spin_lock_bh(rt_hash_lock_addr(hash));
	ip_rt_put(rt);
	while ((aux = *rthp) != NULL) {
		if (aux == rt || (aux->rt_genid != atomic_read(&rt_genid))) {
			*rthp = aux->u.dst.rt_next;
			rt_free(aux);
			continue;
		}
		rthp = &aux->u.dst.rt_next;
	}
	spin_unlock_bh(rt_hash_lock_addr(hash));
}

void ip_rt_redirect(__be32 old_gw, __be32 daddr, __be32 new_gw,
		    __be32 saddr, struct net_device *dev)
{
	int i, k;
	struct in_device *in_dev = in_dev_get(dev);
	struct rtable *rth, **rthp;
	__be32  skeys[2] = { saddr, 0 };
	int  ikeys[2] = { dev->ifindex, 0 };
	struct netevent_redirect netevent;
	struct net *net;

	if (!in_dev)
		return;

	net = dev_net(dev);
	if (new_gw == old_gw || !IN_DEV_RX_REDIRECTS(in_dev)
	    || ipv4_is_multicast(new_gw) || ipv4_is_lbcast(new_gw)
	    || ipv4_is_zeronet(new_gw))
		goto reject_redirect;

	if (!IN_DEV_SHARED_MEDIA(in_dev)) {
		if (!inet_addr_onlink(in_dev, new_gw, old_gw))
			goto reject_redirect;
		if (IN_DEV_SEC_REDIRECTS(in_dev) && ip_fib_check_default(new_gw, dev))
			goto reject_redirect;
	} else {
		if (inet_addr_type(net, new_gw) != RTN_UNICAST)
			goto reject_redirect;
	}

	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++) {
			unsigned hash = rt_hash(daddr, skeys[i], ikeys[k]);

			rthp=&rt_hash_table[hash].chain;

			rcu_read_lock();
			while ((rth = rcu_dereference(*rthp)) != NULL) {
				struct rtable *rt;

				if (rth->fl.fl4_dst != daddr ||
				    rth->fl.fl4_src != skeys[i] ||
				    rth->fl.oif != ikeys[k] ||
				    rth->fl.iif != 0 ||
				    rth->rt_genid != atomic_read(&rt_genid) ||
				    !net_eq(dev_net(rth->u.dst.dev), net)) {
					rthp = &rth->u.dst.rt_next;
					continue;
				}

				if (rth->rt_dst != daddr ||
				    rth->rt_src != saddr ||
				    rth->u.dst.error ||
				    rth->rt_gateway != old_gw ||
				    rth->u.dst.dev != dev)
					break;

				dst_hold(&rth->u.dst);
				rcu_read_unlock();

				rt = dst_alloc(&ipv4_dst_ops);
				if (rt == NULL) {
					ip_rt_put(rth);
					in_dev_put(in_dev);
					return;
				}

				/* Copy all the information. */
				*rt = *rth;
				INIT_RCU_HEAD(&rt->u.dst.rcu_head);
				rt->u.dst.__use		= 1;
				atomic_set(&rt->u.dst.__refcnt, 1);
				rt->u.dst.child		= NULL;
				if (rt->u.dst.dev)
					dev_hold(rt->u.dst.dev);
				if (rt->idev)
					in_dev_hold(rt->idev);
				rt->u.dst.obsolete	= 0;
				rt->u.dst.lastuse	= jiffies;
				rt->u.dst.path		= &rt->u.dst;
				rt->u.dst.neighbour	= NULL;
				rt->u.dst.hh		= NULL;
				rt->u.dst.xfrm		= NULL;
				rt->rt_genid		= atomic_read(&rt_genid);
				rt->rt_flags		|= RTCF_REDIRECTED;

				/* Gateway is different ... */
				rt->rt_gateway		= new_gw;

				/* Redirect received -> path was valid */
				dst_confirm(&rth->u.dst);

				if (rt->peer)
					atomic_inc(&rt->peer->refcnt);

				if (arp_bind_neighbour(&rt->u.dst) ||
				    !(rt->u.dst.neighbour->nud_state &
					    NUD_VALID)) {
					if (rt->u.dst.neighbour)
						neigh_event_send(rt->u.dst.neighbour, NULL);
					ip_rt_put(rth);
					rt_drop(rt);
					goto do_next;
				}

				netevent.old = &rth->u.dst;
				netevent.new = &rt->u.dst;
				call_netevent_notifiers(NETEVENT_REDIRECT,
							&netevent);

				rt_del(hash, rth);
				if (!rt_intern_hash(hash, rt, &rt))
					ip_rt_put(rt);
				goto do_next;
			}
			rcu_read_unlock();
		do_next:
			;
		}
	}
	in_dev_put(in_dev);
	return;

reject_redirect:
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_INFO "Redirect from " NIPQUAD_FMT " on %s about "
			NIPQUAD_FMT " ignored.\n"
			"  Advised path = " NIPQUAD_FMT " -> " NIPQUAD_FMT "\n",
		       NIPQUAD(old_gw), dev->name, NIPQUAD(new_gw),
		       NIPQUAD(saddr), NIPQUAD(daddr));
#endif
	in_dev_put(in_dev);
}

static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable *)dst;
	struct dst_entry *ret = dst;

	if (rt) {
		if (dst->obsolete) {
			ip_rt_put(rt);
			ret = NULL;
		} else if ((rt->rt_flags & RTCF_REDIRECTED) ||
			   rt->u.dst.expires) {
			unsigned hash = rt_hash(rt->fl.fl4_dst, rt->fl.fl4_src,
						rt->fl.oif);
#if RT_CACHE_DEBUG >= 1
			printk(KERN_DEBUG "ipv4_negative_advice: redirect to "
					  NIPQUAD_FMT "/%02x dropped\n",
				NIPQUAD(rt->rt_dst), rt->fl.fl4_tos);
#endif
			rt_del(hash, rt);
			ret = NULL;
		}
	}
	return ret;
}

/*
 * Algorithm:
 *	1. The first ip_rt_redirect_number redirects are sent
 *	   with exponential backoff, then we stop sending them at all,
 *	   assuming that the host ignores our redirects.
 *	2. If we did not see packets requiring redirects
 *	   during ip_rt_redirect_silence, we assume that the host
 *	   forgot redirected route and start to send redirects again.
 *
 * This algorithm is much cheaper and more intelligent than dumb load limiting
 * in icmp.c.
 *
 * NOTE. Do not forget to inhibit load limiting for redirects (redundant)
 * and "frag. need" (breaks PMTU discovery) in icmp.c.
 */

void ip_rt_send_redirect(struct sk_buff *skb)
{
	struct rtable *rt = skb->rtable;
	struct in_device *in_dev = in_dev_get(rt->u.dst.dev);

	if (!in_dev)
		return;

	if (!IN_DEV_TX_REDIRECTS(in_dev))
		goto out;

	/* No redirected packets during ip_rt_redirect_silence;
	 * reset the algorithm.
	 */
	if (time_after(jiffies, rt->u.dst.rate_last + ip_rt_redirect_silence))
		rt->u.dst.rate_tokens = 0;

	/* Too many ignored redirects; do not send anything
	 * set u.dst.rate_last to the last seen redirected packet.
	 */
	if (rt->u.dst.rate_tokens >= ip_rt_redirect_number) {
		rt->u.dst.rate_last = jiffies;
		goto out;
	}

	/* Check for load limit; set rate_last to the latest sent
	 * redirect.
	 */
	if (rt->u.dst.rate_tokens == 0 ||
	    time_after(jiffies,
		       (rt->u.dst.rate_last +
			(ip_rt_redirect_load << rt->u.dst.rate_tokens)))) {
		icmp_send(skb, ICMP_REDIRECT, ICMP_REDIR_HOST, rt->rt_gateway);
		rt->u.dst.rate_last = jiffies;
		++rt->u.dst.rate_tokens;
#ifdef CONFIG_IP_ROUTE_VERBOSE
		if (IN_DEV_LOG_MARTIANS(in_dev) &&
		    rt->u.dst.rate_tokens == ip_rt_redirect_number &&
		    net_ratelimit())
			printk(KERN_WARNING "host " NIPQUAD_FMT "/if%d ignores "
				"redirects for " NIPQUAD_FMT " to " NIPQUAD_FMT ".\n",
				NIPQUAD(rt->rt_src), rt->rt_iif,
				NIPQUAD(rt->rt_dst), NIPQUAD(rt->rt_gateway));
#endif
	}
out:
	in_dev_put(in_dev);
}

static int ip_error(struct sk_buff *skb)
{
	struct rtable *rt = skb->rtable;
	unsigned long now;
	int code;

	switch (rt->u.dst.error) {
		case EINVAL:
		default:
			goto out;
		case EHOSTUNREACH:
			code = ICMP_HOST_UNREACH;
			break;
		case ENETUNREACH:
			code = ICMP_NET_UNREACH;
			IP_INC_STATS_BH(IPSTATS_MIB_INNOROUTES);
			break;
		case EACCES:
			code = ICMP_PKT_FILTERED;
			break;
	}

	now = jiffies;
	rt->u.dst.rate_tokens += now - rt->u.dst.rate_last;
	if (rt->u.dst.rate_tokens > ip_rt_error_burst)
		rt->u.dst.rate_tokens = ip_rt_error_burst;
	rt->u.dst.rate_last = now;
	if (rt->u.dst.rate_tokens >= ip_rt_error_cost) {
		rt->u.dst.rate_tokens -= ip_rt_error_cost;
		icmp_send(skb, ICMP_DEST_UNREACH, code, 0);
	}

out:	kfree_skb(skb);
	return 0;
}

/*
 *	The last two values are not from the RFC but
 *	are needed for AMPRnet AX.25 paths.
 */

static const unsigned short mtu_plateau[] =
{32000, 17914, 8166, 4352, 2002, 1492, 576, 296, 216, 128 };

static inline unsigned short guess_mtu(unsigned short old_mtu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mtu_plateau); i++)
		if (old_mtu > mtu_plateau[i])
			return mtu_plateau[i];
	return 68;
}

unsigned short ip_rt_frag_needed(struct net *net, struct iphdr *iph,
				 unsigned short new_mtu,
				 struct net_device *dev)
{
	int i, k;
	unsigned short old_mtu = ntohs(iph->tot_len);
	struct rtable *rth;
	int  ikeys[2] = { dev->ifindex, 0 };
	__be32  skeys[2] = { iph->saddr, 0, };
	__be32  daddr = iph->daddr;
	unsigned short est_mtu = 0;

	if (ipv4_config.no_pmtu_disc)
		return 0;

	for (k = 0; k < 2; k++) {
		for (i = 0; i < 2; i++) {
			unsigned hash = rt_hash(daddr, skeys[i], ikeys[k]);

			rcu_read_lock();
			for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
			     rth = rcu_dereference(rth->u.dst.rt_next)) {
				unsigned short mtu = new_mtu;

				if (rth->fl.fl4_dst != daddr ||
				    rth->fl.fl4_src != skeys[i] ||
				    rth->rt_dst != daddr ||
				    rth->rt_src != iph->saddr ||
				    rth->fl.oif != ikeys[k] ||
				    rth->fl.iif != 0 ||
				    dst_metric_locked(&rth->u.dst, RTAX_MTU) ||
				    !net_eq(dev_net(rth->u.dst.dev), net) ||
				    rth->rt_genid != atomic_read(&rt_genid))
					continue;

				if (new_mtu < 68 || new_mtu >= old_mtu) {

					/* BSD 4.2 compatibility hack :-( */
					if (mtu == 0 &&
					    old_mtu >= dst_metric(&rth->u.dst, RTAX_MTU) &&
					    old_mtu >= 68 + (iph->ihl << 2))
						old_mtu -= iph->ihl << 2;

					mtu = guess_mtu(old_mtu);
				}
				if (mtu <= dst_metric(&rth->u.dst, RTAX_MTU)) {
					if (mtu < dst_metric(&rth->u.dst, RTAX_MTU)) {
						dst_confirm(&rth->u.dst);
						if (mtu < ip_rt_min_pmtu) {
							mtu = ip_rt_min_pmtu;
							rth->u.dst.metrics[RTAX_LOCK-1] |=
								(1 << RTAX_MTU);
						}
						rth->u.dst.metrics[RTAX_MTU-1] = mtu;
						dst_set_expires(&rth->u.dst,
							ip_rt_mtu_expires);
					}
					est_mtu = mtu;
				}
			}
			rcu_read_unlock();
		}
	}
	return est_mtu ? : new_mtu;
}

static void ip_rt_update_pmtu(struct dst_entry *dst, u32 mtu)
{
	if (dst_metric(dst, RTAX_MTU) > mtu && mtu >= 68 &&
	    !(dst_metric_locked(dst, RTAX_MTU))) {
		if (mtu < ip_rt_min_pmtu) {
			mtu = ip_rt_min_pmtu;
			dst->metrics[RTAX_LOCK-1] |= (1 << RTAX_MTU);
		}
		dst->metrics[RTAX_MTU-1] = mtu;
		dst_set_expires(dst, ip_rt_mtu_expires);
		call_netevent_notifiers(NETEVENT_PMTU_UPDATE, dst);
	}
}

static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie)
{
	return NULL;
}

static void ipv4_dst_destroy(struct dst_entry *dst)
{
	struct rtable *rt = (struct rtable *) dst;
	struct inet_peer *peer = rt->peer;
	struct in_device *idev = rt->idev;

	if (peer) {
		rt->peer = NULL;
		inet_putpeer(peer);
	}

	if (idev) {
		rt->idev = NULL;
		in_dev_put(idev);
	}
}

static void ipv4_dst_ifdown(struct dst_entry *dst, struct net_device *dev,
			    int how)
{
	struct rtable *rt = (struct rtable *) dst;
	struct in_device *idev = rt->idev;
	if (dev != dev_net(dev)->loopback_dev && idev && idev->dev == dev) {
		struct in_device *loopback_idev =
			in_dev_get(dev_net(dev)->loopback_dev);
		if (loopback_idev) {
			rt->idev = loopback_idev;
			in_dev_put(idev);
		}
	}
}

static void ipv4_link_failure(struct sk_buff *skb)
{
	struct rtable *rt;

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

	rt = skb->rtable;
	if (rt)
		dst_set_expires(&rt->u.dst, 0);
}

static int ip_rt_bug(struct sk_buff *skb)
{
	printk(KERN_DEBUG "ip_rt_bug: " NIPQUAD_FMT " -> " NIPQUAD_FMT ", %s\n",
		NIPQUAD(ip_hdr(skb)->saddr), NIPQUAD(ip_hdr(skb)->daddr),
		skb->dev ? skb->dev->name : "?");
	kfree_skb(skb);
	return 0;
}

/*
   We do not cache source address of outgoing interface,
   because it is used only by IP RR, TS and SRR options,
   so that it out of fast path.

   BTW remember: "addr" is allowed to be not aligned
   in IP options!
 */

void ip_rt_get_source(u8 *addr, struct rtable *rt)
{
	__be32 src;
	struct fib_result res;

	if (rt->fl.iif == 0)
		src = rt->rt_src;
	else if (fib_lookup(dev_net(rt->u.dst.dev), &rt->fl, &res) == 0) {
		src = FIB_RES_PREFSRC(res);
		fib_res_put(&res);
	} else
		src = inet_select_addr(rt->u.dst.dev, rt->rt_gateway,
					RT_SCOPE_UNIVERSE);
	memcpy(addr, &src, 4);
}

#ifdef CONFIG_NET_CLS_ROUTE
static void set_class_tag(struct rtable *rt, u32 tag)
{
	if (!(rt->u.dst.tclassid & 0xFFFF))
		rt->u.dst.tclassid |= tag & 0xFFFF;
	if (!(rt->u.dst.tclassid & 0xFFFF0000))
		rt->u.dst.tclassid |= tag & 0xFFFF0000;
}
#endif

static void rt_set_nexthop(struct rtable *rt, struct fib_result *res, u32 itag)
{
	struct fib_info *fi = res->fi;//取得查找结果中的路由信息结构

	if (fi) {//如果存在路由信息结构，如果指定了网关并且跳转范围在子网范围
		if (FIB_RES_GW(*res) &&
		    FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
			rt->rt_gateway = FIB_RES_GW(*res);//记录查找结果中的网关地址
		memcpy(rt->u.dst.metrics, fi->fib_metrics,
		       sizeof(rt->u.dst.metrics));//复制路由信息的负载值到路由项中
		if (fi->fib_mtu == 0) {//如果路由信息的MTU值为 0
			rt->u.dst.metrics[RTAX_MTU-1] = rt->u.dst.dev->mtu;//复制设备的MTU值到路由项中
			if (dst_metric_locked(&rt->u.dst, RTAX_MTU) &&
			    rt->rt_gateway != rt->rt_dst &&
			    rt->u.dst.dev->mtu > 576)
				rt->u.dst.metrics[RTAX_MTU-1] = 576;//修改 MTU的负载值
		}
#ifdef CONFIG_NET_CLS_ROUTE
		rt->u.dst.tclassid = FIB_RES_NH(*res).nh_tclassid;
#endif
	} else//没有路由信息结构就使用设备的 MTU
		rt->u.dst.metrics[RTAX_MTU-1]= rt->u.dst.dev->mtu;//记录设备的MTU
	//设置各种负载值
	if (dst_metric(&rt->u.dst, RTAX_HOPLIMIT) == 0)
		rt->u.dst.metrics[RTAX_HOPLIMIT-1] = sysctl_ip_default_ttl;//跳转限制值
	if (dst_metric(&rt->u.dst, RTAX_MTU) > IP_MAX_MTU)
		rt->u.dst.metrics[RTAX_MTU-1] = IP_MAX_MTU;//MTU
	if (dst_metric(&rt->u.dst, RTAX_ADVMSS) == 0)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = max_t(unsigned int, rt->u.dst.dev->mtu - 40,
				       ip_rt_min_advmss);//对外公开的MSS值
	if (dst_metric(&rt->u.dst, RTAX_ADVMSS) > 65535 - 40)
		rt->u.dst.metrics[RTAX_ADVMSS-1] = 65535 - 40;

#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	set_class_tag(rt, fib_rules_tclass(res));
#endif
	set_class_tag(rt, itag);
#endif
	rt->rt_type = res->type;//记录查询结果中的路由类型
}

static int ip_route_input_mc(struct sk_buff *skb, __be32 daddr, __be32 saddr,
				u8 tos, struct net_device *dev, int our)
{
	unsigned hash;
	struct rtable *rth;
	__be32 spec_dst;
	struct in_device *in_dev = in_dev_get(dev);
	u32 itag = 0;

	/* Primary sanity checks. */

	if (in_dev == NULL)
		return -EINVAL;

	if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr) ||
	    ipv4_is_loopback(saddr) || skb->protocol != htons(ETH_P_IP))
		goto e_inval;

	if (ipv4_is_zeronet(saddr)) {
		if (!ipv4_is_local_multicast(daddr))
			goto e_inval;
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);
	} else if (fib_validate_source(saddr, 0, tos, 0,
					dev, &spec_dst, &itag) < 0)
		goto e_inval;

	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth)
		goto e_nobufs;

	rth->u.dst.output= ip_rt_bug;

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= init_net.loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif	= 0;
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	rth->rt_genid	= atomic_read(&rt_genid);
	rth->rt_flags	= RTCF_MULTICAST;
	rth->rt_type	= RTN_MULTICAST;
	if (our) {
		rth->u.dst.input= ip_local_deliver;
		rth->rt_flags |= RTCF_LOCAL;
	}

#ifdef CONFIG_IP_MROUTE
	if (!ipv4_is_local_multicast(daddr) && IN_DEV_MFORWARD(in_dev))
		rth->u.dst.input = ip_mr_input;
#endif
	RT_CACHE_STAT_INC(in_slow_mc);

	in_dev_put(in_dev);
	hash = rt_hash(daddr, saddr, dev->ifindex);
	return rt_intern_hash(hash, rth, &skb->rtable);

e_nobufs:
	in_dev_put(in_dev);
	return -ENOBUFS;

e_inval:
	in_dev_put(in_dev);
	return -EINVAL;
}


static void ip_handle_martian_source(struct net_device *dev,
				     struct in_device *in_dev,
				     struct sk_buff *skb,
				     __be32 daddr,
				     __be32 saddr)
{
	RT_CACHE_STAT_INC(in_martian_src);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit()) {
		/*
		 *	RFC1812 recommendation, if source is martian,
		 *	the only hint is MAC header.
		 */
		printk(KERN_WARNING "martian source " NIPQUAD_FMT " from "
			NIPQUAD_FMT", on dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
		if (dev->hard_header_len && skb_mac_header_was_set(skb)) {
			int i;
			const unsigned char *p = skb_mac_header(skb);
			printk(KERN_WARNING "ll header: ");
			for (i = 0; i < dev->hard_header_len; i++, p++) {
				printk("%02x", *p);
				if (i < (dev->hard_header_len - 1))
					printk(":");
			}
			printk("\n");
		}
	}
#endif
}
/*

功能:创建一个输入路由缓存项。
1.对路由进行合法性检查
2.调用dst_alloc创建路由缓存项
3.设置路由缓存的输入、输出函数指针

*/
static int __mkroute_input(struct sk_buff *skb,
			   struct fib_result *res,
			   struct in_device *in_dev,
			   __be32 daddr, __be32 saddr, u32 tos,
			   struct rtable **result)
{

	struct rtable *rth;
	int err;
	struct in_device *out_dev;
	unsigned flags = 0;
	__be32 spec_dst;
	u32 itag;

	/* get a working reference to the output device */
	out_dev = in_dev_get(FIB_RES_DEV(*res));//取得输出设备的配置结构
	if (out_dev == NULL) {//如果没有配置结构就打印出错信息返回
		if (net_ratelimit())
			printk(KERN_CRIT "Bug in ip_route_input" \
			       "_slow(). Please, report\n");
		return -EINVAL;
	}

	/*路由合法性检查，当调用该函数前，已经找到了一个从saddr->daddr的路由项，
	而该函数的功能是创建该路由项对应的路由缓存。但是创建路由缓存之前，
	我们需要对该路由项进行合法性检查，即判断daddr->saddr的反向路由是否存在，
	若不存在，则说明从saddr->daddr的路由是有问题的，则该函数会返回错误*/
	err = fib_validate_source(saddr, daddr, tos, FIB_RES_OIF(*res),
				  in_dev->dev, &spec_dst, &itag);
	if (err < 0) {
		ip_handle_martian_source(in_dev->dev, in_dev, skb, daddr,
					 saddr);//打印源地址错误信息

		err = -EINVAL;
		goto cleanup;
	}

	if (err)
		flags |= RTCF_DIRECTSRC;
	//检查配置结构和地址
	if (out_dev == in_dev && err &&
	    (IN_DEV_SHARED_MEDIA(out_dev) ||
	     inet_addr_onlink(out_dev, saddr, FIB_RES_GW(*res))))
		flags |= RTCF_DOREDIRECT;

	if (skb->protocol != htons(ETH_P_IP)) {//不是标志的IP协议
		/* Not IP (i.e. ARP). Do not create route, if it is
		 * invalid for proxy arp. DNAT routes are always valid.
		 */
		if (out_dev == in_dev) {
			err = -EINVAL;
			goto cleanup;
		}
	}

	/*创建路由缓存项*/
	rth = dst_alloc(&ipv4_dst_ops);
	if (!rth) {
		err = -ENOBUFS;
		goto cleanup;
	}
	/*对路由缓存项进行初始化*/
	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;
	if (IN_DEV_CONF_GET(out_dev, NOXFRM))
		rth->u.dst.flags |= DST_NOXFRM;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
	rth->rt_gateway	= daddr;
	rth->rt_iif 	=
		rth->fl.iif	= in_dev->dev->ifindex;
	rth->u.dst.dev	= (out_dev)->dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->fl.oif 	= 0;
	rth->rt_spec_dst= spec_dst;
	
	rth->u.dst.input = ip_forward;
	rth->u.dst.output = ip_output;
	rth->rt_genid = atomic_read(&rt_genid);
	/*设置下一跳ip*/
	rt_set_nexthop(rth, res, itag);

	rth->rt_flags = flags;

	*result = rth;
	err = 0;
 cleanup:
	/* release the working reference to the output device */
	in_dev_put(out_dev);
	return err;
}

static int ip_mkroute_input(struct sk_buff *skb,
			    struct fib_result *res,
			    const struct flowi *fl,
			    struct in_device *in_dev,
			    __be32 daddr, __be32 saddr, u32 tos)
{
	struct rtable* rth = NULL;
	int err;
	unsigned hash;

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	//多路径选项
	if (res->fi && res->fi->fib_nhs > 1 && fl->oif == 0)
		fib_select_multipath(fl, res);//优先跳转结构
#endif

	/* create a routing cache entry */
	err = __mkroute_input(skb, res, in_dev, daddr, saddr, tos, &rth);//创建路由缓存项
	if (err)
		return err;

	/* put it into the cache */
	hash = rt_hash(daddr, saddr, fl->iif);//计算hash值
	return rt_intern_hash(hash, rth, &skb->rtable);//将路由表链入哈希队列并记录到数据包中
}

/*
 *	NOTE. We drop all the packets that has local source
 *	addresses, because every properly looped back packet
 *	must have correct destination already attached by output routine.
 *
 *	Such approach solves two big problems:
 *	1. Not simplex devices are handled properly.
 *	2. IP spoofing attempts are filtered with 100% of guarantee.
 */
/*
该函数主要完成两个功能:
1.通过调用fib_lookup进行路由表查找
2.若在路由表中查找到符合条件的路由，则调用ip_mkroute_input创建
   路由缓存，并将路由缓存与arp邻居项实现绑定。
对于fib_lookup来说，若系统支持策略路由，则首先进行策略规则的匹配，
然后根据策略规则找到相应的路由表，这就涉及到策略规则与路由表查找
相关的内容，关于这两方面的内容可以查看"路由表的查找"与"策略规则的查找"
的内容。而对于ip_mkroute_input中，路由缓存与arp邻居项的绑定，可以查看“路由缓存相关的创建”与“邻居项相关”的分析文档。
这个函数将路由项查找、策略规则查找、路由缓存创建、路由缓存与邻居项的绑定关联了起来，是一个比较综合的接口函数。
https://jerry-cheng.blog.csdn.net/article/details/41683671
*/
static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
			       u8 tos, struct net_device *dev)
{
	struct fib_result res;
	/*获取输入设备的三层参数*/
	struct in_device *in_dev = in_dev_get(dev);//获取设配的配置结构
	//根据传入的值，构造查找条件
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = daddr,
					.saddr = saddr,
					.tos = tos,
					.scope = RT_SCOPE_UNIVERSE,
				      } },
			    .mark = skb->mark,
			    .iif = dev->ifindex };
	unsigned	flags = 0;
	u32		itag = 0;
	struct rtable * rth;
	unsigned	hash;
	__be32		spec_dst;
	int		err = -EINVAL;
	int		free_res = 0;
	struct net    * net = dev_net(dev);

	/* IP on this device is disabled. */
	/*当该设备没有设置三层参数，则程序返回错误*/
	if (!in_dev)
		goto out;

	/* Check for the most weird martians, which can be not detected
	   by fib_lookup.
	 */
	/*当源ip地址为组播、广播或者环回地址，则返回错误。*/
	if (ipv4_is_multicast(saddr) || ipv4_is_lbcast(saddr) ||
	    ipv4_is_loopback(saddr))
		goto martian_source;
	//如果目标地址为广播地址，或者源地址和目标地址同时为零地址
	if (daddr == htonl(0xFFFFFFFF) || (saddr == 0 && daddr == 0))
		goto brd_input;//跳转到广播处理流程

	/* Accept zero addresses only to limited broadcast;
	 * I even do not know to fix it or not. Waiting for complains :-)
	 */
	if (ipv4_is_zeronet(saddr))//广播地址位零网地址类型
		goto martian_source;//源地址错误，跳转

	if (ipv4_is_lbcast(daddr) || ipv4_is_zeronet(daddr) ||
	    ipv4_is_loopback(daddr))//如果目标地址为广播地址、零地址或者回环地址
		goto martian_destination;//目标地址错误

	/*
	 *	Now we are ready to route packet.
	 */
	if ((err = fib_lookup(net, &fl, &res)) != 0) {//通过路由函数表查找目标地址
		if (!IN_DEV_FORWARD(in_dev))//如果设备不支持转发
			goto e_hostunreach;//主机无法到达错误，跳转
		goto no_route;//无法到达，跳转
	}
	free_res = 1;//默认为释放查找结果

	RT_CACHE_STAT_INC(in_slow_tot);//递增计数

	if (res.type == RTN_BROADCAST)//路由类型为广播
		goto brd_input;//跳转到广播处理流程
	/*对于路由类型为local的路由项，则跳转到local_input标签进行处理*/
	if (res.type == RTN_LOCAL) {//路由类型local
		int result;
		result = fib_validate_source(saddr, daddr, tos,
					     net->loopback_dev->ifindex,
					     dev, &spec_dst, &itag);//检查源地址
		if (result < 0)
			goto martian_source;//源地址错误
		if (result)
			flags |= RTCF_DIRECTSRC;
		spec_dst = daddr;//记录目标地址
		goto local_input;//本地输入跳转
	}

	if (!IN_DEV_FORWARD(in_dev))//如果设备不支持转发
		goto e_hostunreach;//主机无法到达错误
	if (res.type != RTN_UNICAST)//目标地址不是单播类型
		goto martian_destination;//目标地址错误，跳转
	//创建用于转发的路由表
	err = ip_mkroute_input(skb, &res, &fl, in_dev, daddr, saddr, tos);
done:
	in_dev_put(in_dev);
	if (free_res)
		fib_res_put(&res);
out:	return err;

brd_input://广播处理流程
	if (skb->protocol != htons(ETH_P_IP))//是否是IP协议
		goto e_inval;//错误

	if (ipv4_is_zeronet(saddr))//源地址是零网地址类型
		spec_dst = inet_select_addr(dev, 0, RT_SCOPE_LINK);//选择目标地址
	else {
		err = fib_validate_source(saddr, 0, tos, 0, dev, &spec_dst,
					  &itag);//检查源地址
		if (err < 0)
			goto martian_source;
		if (err)
			flags |= RTCF_DIRECTSRC;
	}
	flags |= RTCF_BROADCAST;//增加广播标志
	res.type = RTN_BROADCAST;//设置地址类型为广播类型
	RT_CACHE_STAT_INC(in_brd);

local_input:
	rth = dst_alloc(&ipv4_dst_ops);//创建缓存路由表
	if (!rth)
		goto e_nobufs;

	rth->u.dst.output= ip_rt_bug;//设置输出方向的函数，以为是发往本地，所以不存在outpu流程，这里直接设置成ip_rt_bug函数
	rth->rt_genid = atomic_read(&rt_genid);//记录随机值

	atomic_set(&rth->u.dst.__refcnt, 1);
	rth->u.dst.flags= DST_HOST;//设置路由标志
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))
		rth->u.dst.flags |= DST_NOPOLICY;
	rth->fl.fl4_dst	= daddr;
	rth->rt_dst	= daddr;
	rth->fl.fl4_tos	= tos;
	rth->fl.mark    = skb->mark;
	rth->fl.fl4_src	= saddr;
	rth->rt_src	= saddr;
#ifdef CONFIG_NET_CLS_ROUTE
	rth->u.dst.tclassid = itag;
#endif
	rth->rt_iif	=
	rth->fl.iif	= dev->ifindex;
	rth->u.dst.dev	= net->loopback_dev;
	dev_hold(rth->u.dst.dev);
	rth->idev	= in_dev_get(rth->u.dst.dev);
	rth->rt_gateway	= daddr;
	rth->rt_spec_dst= spec_dst;
	rth->u.dst.input= ip_local_deliver;
	rth->rt_flags 	= flags|RTCF_LOCAL;//增加本地路由标志
	if (res.type == RTN_UNREACHABLE) {//如果设置的目标不可达
		rth->u.dst.input= ip_error;//设置错误处理函数
		rth->u.dst.error= -err;//设置错误码
		rth->rt_flags 	&= ~RTCF_LOCAL;//清除本地路由标志
	}
	rth->rt_type	= res.type;//记录目标地址类型
	//根据目标地址、源地址、入接口(因在在input流程中)计算hash
	hash = rt_hash(daddr, saddr, fl.iif);
	err = rt_intern_hash(hash, rth, &skb->rtable);//将路由表插人哈希队列并记录到数据包中
	goto done;//返回

no_route://无法达到
	RT_CACHE_STAT_INC(in_no_route);
	spec_dst = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);//确定指定目标
	res.type = RTN_UNREACHABLE;//设置不可到达
	if (err == -ESRCH)
		err = -ENETUNREACH;
	goto local_input;//本地输入，跳转

	/*
	 *	Do not cache martian addresses: they should be logged (RFC1812)
	 */
martian_destination://目标地址错误
	RT_CACHE_STAT_INC(in_martian_dst);
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev) && net_ratelimit())
		printk(KERN_WARNING "martian destination " NIPQUAD_FMT " from "
			NIPQUAD_FMT ", dev %s\n",
			NIPQUAD(daddr), NIPQUAD(saddr), dev->name);
#endif

e_hostunreach://主机不可到达错误
	err = -EHOSTUNREACH;
	goto done;

e_inval://无法识别错误
	err = -EINVAL;
	goto done;

e_nobufs://空间不足
	err = -ENOBUFS;
	goto done;

martian_source://源地址错误
	ip_handle_martian_source(dev, in_dev, skb, daddr, saddr);
	goto e_inval;
}
/*
对于输入的数据包，会有三个输出结果:
1.本机接收
2.本机转发
3.丢掉数据包
这个函数根据不同的查找结果，会有两个分支:
1.当路由缓存中已存在该数据包对应的路由，则通过查找相应的路由缓存表即可(rt_hash_table[hash].chain)
2.当路由缓存中不存在该数据包对应的路由时，则通过调用ip_route_input_slow，通过查找路由表，来决定数据包的命运。这个函数就综合了策略规则的查找、路由项的查找、路由缓存的查找、路由缓存的生成、路由缓存与arp邻居项的绑定。
*/
int ip_route_input(struct sk_buff *skb, __be32 daddr, __be32 saddr,
		   u8 tos, struct net_device *dev)
{
	struct rtable * rth;
	unsigned	hash;
	int iif = dev->ifindex;//获取设备ID
	struct net *net;

	net = dev_net(dev);//获取命名空间
	tos &= IPTOS_RT_MASK; //调整TOS值
	hash = rt_hash(daddr, saddr, iif);//计算hash值

	rcu_read_lock();
	/*在hash数组rt_hash_table中，根据hash值找到相应的hash链表，遍历链表中的所用rtable成员，查找符合条件的路由缓存，若找到的则返回0，并将skb->dst指向该路由缓存。
	ip_rcv_finish就会调用skb->dst->input，对数据包进行处理，而在创建路由缓存时，已经将dst->input的值设置为ip_local_deliver或者ip_forward，根据skb->dst->input函数，就决定了数据包是
	发送给本机上层协议进行处理还是转发出去。
	*/
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
	     rth = rcu_dereference(rth->u.dst.rt_next)) {
		/* 循环在路由表队列中查找路由表,条件是地址相同服务类型相同掩码相同网络空间相同、随机数相同 */
		if (((rth->fl.fl4_dst ^ daddr) |
		     (rth->fl.fl4_src ^ saddr) |
		     (rth->fl.iif ^ iif) |
		     rth->fl.oif |
		     (rth->fl.fl4_tos ^ tos)) == 0 &&
		    rth->fl.mark == skb->mark &&
		    net_eq(dev_net(rth->u.dst.dev), net) &&
		    rth->rt_genid == atomic_read(&rt_genid)) {
			dst_use(&rth->u.dst, jiffies);
			RT_CACHE_STAT_INC(in_hit);
			rcu_read_unlock();
			skb->rtable = rth;//找到具体的缓存路由
			return 0;
		}
		RT_CACHE_STAT_INC(in_hlist_search);
	}
	rcu_read_unlock();

	/* Multicast recognition logic is moved from route cache to here.
	   The problem was that too many Ethernet cards have broken/missing
	   hardware multicast filters :-( As result the host on multicasting
	   network acquires a lot of useless route cache entries, sort of
	   SDR messages from all the world. Now we try to get rid of them.
	   Really, provided software IP multicast filter is organized
	   reasonably (at least, hashed), it does not result in a slowdown
	   comparing with route cache reject entries.
	   Note, that multicast routers are not affected, because
	   route cache entry is created eventually.
	 */
	if (ipv4_is_multicast(daddr)) { /*路由缓存没有命中，且目的地址为组播地址时，则进入组播处理流程*/
		struct in_device *in_dev;

		rcu_read_lock();
		if ((in_dev = __in_dev_get_rcu(dev)) != NULL) {//获取配置结构
			int our = ip_check_mc(in_dev, daddr, saddr,
				ip_hdr(skb)->protocol);//检查目标地址是否为本地配置组播地址
			if (our
#ifdef CONFIG_IP_MROUTE
			    || (!ipv4_is_local_multicast(daddr) &&
				IN_DEV_MFORWARD(in_dev))
#endif
			    ) {
				rcu_read_unlock();
				return ip_route_input_mc(skb, daddr, saddr,
							 tos, dev, our);//为组播创建路由表
			}
		}
		rcu_read_unlock();
		return -EINVAL;
	}
	/*当路由缓存查找没有命中，且目的地址不是组播地址时，则调用ip_route_input_slow进行路由项的查找*/
	return ip_route_input_slow(skb, daddr, saddr, tos, dev);
}
/*
功能:创建一个输入路由缓存项。
1.对路由项的类型进行判断，并执行相应的判断。
2.调用dst_alloc创建路由缓存项
3.设置路由缓存的输出函数指针
*/
static int __mkroute_output(struct rtable **result,
			    struct fib_result *res,
			    const struct flowi *fl,
			    const struct flowi *oldflp,
			    struct net_device *dev_out,
			    unsigned flags)
{
	struct rtable *rth;
	struct in_device *in_dev;
	u32 tos = RT_FL_TOS(oldflp);
	int err = 0;
	//源地址是回接地址，但是发送设备不支持回接就返回
	if (ipv4_is_loopback(fl->fl4_src) && !(dev_out->flags&IFF_LOOPBACK))
		return -EINVAL;

	if (fl->fl4_dst == htonl(0xFFFFFFFF))//目标地址是否为广播地址
		res->type = RTN_BROADCAST;//设置查询结果返回的类型为广播类型
	else if (ipv4_is_multicast(fl->fl4_dst))//目标地址是否为组播地址
		res->type = RTN_MULTICAST;//设置查询结果返回的类型为组播类型
	else if (ipv4_is_lbcast(fl->fl4_dst) || ipv4_is_zeronet(fl->fl4_dst))//是否位广播地址或者零网地址
		return -EINVAL;

	if (dev_out->flags & IFF_LOOPBACK)//发送设备支持环回
		flags |= RTCF_LOCAL;//增加本地路由标志

	/* get work reference to inet device */
	in_dev = in_dev_get(dev_out);//获取配置结构
	if (!in_dev)
		return -EINVAL;

	if (res->type == RTN_BROADCAST) {//如果时广播类型
		flags |= RTCF_BROADCAST | RTCF_LOCAL;//则增加广播和本地路由标志
		if (res->fi) {//放弃使用路由信息结构
			fib_info_put(res->fi);
			res->fi = NULL;
		}
	} else if (res->type == RTN_MULTICAST) {//如果是组播地址
		flags |= RTCF_MULTICAST|RTCF_LOCAL;//增加组播和本地路由标志
		if (!ip_check_mc(in_dev, oldflp->fl4_dst, oldflp->fl4_src,
				 oldflp->proto))
			flags &= ~RTCF_LOCAL;
		/* If multicast route do not exist use
		   default one, but do not gateway in this case.
		   Yes, it is hack.
		 */
		if (res->fi && res->prefixlen < 4) {//放弃使用路由信息结构
			fib_info_put(res->fi);
			res->fi = NULL;
		}
	}


	rth = dst_alloc(&ipv4_dst_ops);//分配缓存路由表结构
	if (!rth) {
		err = -ENOBUFS;
		goto cleanup;
	}

	atomic_set(&rth->u.dst.__refcnt, 1);//设置使用计数
	rth->u.dst.flags= DST_HOST;//路由项增加目标主机标志
	if (IN_DEV_CONF_GET(in_dev, NOXFRM))//如果配置结构中指定无XERM 框架
		rth->u.dst.flags |= DST_NOXFRM; //路由项中增加无 XFRM 框架标志
	if (IN_DEV_CONF_GET(in_dev, NOPOLICY))//如果配置结构指定无策略
		rth->u.dst.flags |= DST_NOPOLICY;// 路由项中增加无策略标志

	rth->fl.fl4_dst	= oldflp->fl4_dst;
	rth->fl.fl4_tos	= tos;
	rth->fl.fl4_src	= oldflp->fl4_src;
	rth->fl.oif	= oldflp->oif;
	rth->fl.mark    = oldflp->mark;
	rth->rt_dst	= fl->fl4_dst;
	rth->rt_src	= fl->fl4_src;
	rth->rt_iif	= oldflp->oif ? : dev_out->ifindex;
	/* get references to the devices that are to be hold by the routing
	   cache entry */
	rth->u.dst.dev	= dev_out;
	dev_hold(dev_out);
	rth->idev	= in_dev_get(dev_out);
	rth->rt_gateway = fl->fl4_dst;
	rth->rt_spec_dst= fl->fl4_src;
	/*对于输出路由缓存项， 则只需设置output的指针即可，其输入指针为初始值(dst_discard_in)*/
	rth->u.dst.output=ip_output;
	rth->rt_genid = atomic_read(&rt_genid);

	RT_CACHE_STAT_INC(out_slow_tot);

	if (flags & RTCF_LOCAL) {//本地转发
		rth->u.dst.input = ip_local_deliver;
		rth->rt_spec_dst = fl->fl4_dst;
	}
	if (flags & (RTCF_BROADCAST | RTCF_MULTICAST)) {//如果是广播或者组播
		rth->rt_spec_dst = fl->fl4_src;//使用源地址作为指定目标
		if (flags & RTCF_LOCAL &&
		    !(dev_out->flags & IFF_LOOPBACK)) {//如果是本地转发但是设备不支持回接
			rth->u.dst.output = ip_mc_output;//设置路由项的发送数据包函数
			RT_CACHE_STAT_INC(out_slow_mc);//递增使用计数
		}
#ifdef CONFIG_IP_MROUTE
		if (res->type == RTN_MULTICAST) {
			if (IN_DEV_MFORWARD(in_dev) &&
			    !ipv4_is_local_multicast(oldflp->fl4_dst)) {
				rth->u.dst.input = ip_mr_input;
				rth->u.dst.output = ip_mc_output;
			}
		}
#endif
	}

	rt_set_nexthop(rth, res, 0);//根据查询结果设置路由表

	rth->rt_flags = flags;//记录标志位

	*result = rth;//返回新建的路由表
 cleanup:
	/* release work reference to inet device */
	in_dev_put(in_dev);//放弃对配置结构的使用

	return err;
}

static int ip_mkroute_output(struct rtable **rp,
			     struct fib_result *res,
			     const struct flowi *fl,
			     const struct flowi *oldflp,
			     struct net_device *dev_out,
			     unsigned flags)
{
	struct rtable *rth = NULL;
	//创建新的路由表
	int err = __mkroute_output(&rth, res, fl, oldflp, dev_out, flags);
	unsigned hash;
	if (err == 0) {
		hash = rt_hash(oldflp->fl4_dst, oldflp->fl4_src, oldflp->oif);//计算hash值
		err = rt_intern_hash(hash, rth, rp);//有hash值确定插入位置，插入对应位置的队列
	}

	return err;
}

/*
 * Major route resolver routine.
 */

static int ip_route_output_slow(struct net *net, struct rtable **rp,
				const struct flowi *oldflp)
{
	u32 tos	= RT_FL_TOS(oldflp);//获取前面设置的TOS值
	//为什么需要从oldflp复制一个fl变量？因为在路由查询过程中，fl变量的值被修改了
	struct flowi fl = { .nl_u = { .ip4_u =
				      { .daddr = oldflp->fl4_dst,//目标地址
					.saddr = oldflp->fl4_src, //源地址
					.proto = oldflp->proto, //协议类型
					.tos = tos & IPTOS_RT_MASK,
					.scope = ((tos & RTO_ONLINK) ?
						  RT_SCOPE_LINK :
						  RT_SCOPE_UNIVERSE),
				      } },
			    .mark = oldflp->mark,
			    .iif = net->loopback_dev->ifindex,
			    .oif = oldflp->oif };
	struct fib_result res; //查找的路由项
	unsigned flags = 0;
	struct net_device *dev_out = NULL;
	int free_res = 0;
	int err;


	res.fi		= NULL;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	res.r		= NULL;
#endif

	if (oldflp->fl4_src) {//如果配置了源地址
		err = -EINVAL;
		//这3类地址不允许使用源地址
		if (ipv4_is_multicast(oldflp->fl4_src) ||//是否是组播地址
		    ipv4_is_lbcast(oldflp->fl4_src) || //是否是广播地址
		    ipv4_is_zeronet(oldflp->fl4_src)) //是否是零网地址。
			goto out;

		/* It is equivalent to inet_addr_type(saddr) == RTN_LOCAL */
		dev_out = ip_dev_find(net, oldflp->fl4_src);//查找发送网络设备，通过源地址
		if (dev_out == NULL)
			goto out;

		/* I removed check for oif == dev_out->oif here.
		   It was wrong for two reasons:
		   1. ip_dev_find(net, saddr) can return wrong iface, if saddr
		      is assigned to multiple interfaces.
		   2. Moreover, we are allowed to send packets with saddr
		      of another iface. --ANK
		 */

		if (oldflp->oif == 0 //没有指定出接口网卡
		    && (ipv4_is_multicast(oldflp->fl4_dst) || //组播地址
			oldflp->fl4_dst == htonl(0xFFFFFFFF))) {//目标地址是受限的广播地址
			/* Special hack: user can direct multicasts
			   and limited broadcast via necessary interface
			   without fiddling with IP_MULTICAST_IF or IP_PKTINFO.
			   This hack is not just for fun, it allows
			   vic,vat and friends to work.
			   They bind socket to loopback, set ttl to zero
			   and expect that it will work.
			   From the viewpoint of routing cache they are broken,
			   because we are not allowed to build multicast path
			   with loopback source addr (look, routing cache
			   cannot know, that ttl is zero, so that packet
			   will not leave this host and route is valid).
			   Luckily, this hack is good workaround.
			 */

			fl.oif = dev_out->ifindex;//记录上面找到的发送设备ID
			goto make_route;
		}
		if (dev_out)
			dev_put(dev_out);//递减发送设备引用计数
		dev_out = NULL;
	}


	if (oldflp->oif) {//指定了发送设备
		dev_out = dev_get_by_index(net, oldflp->oif);//找到指定的发送设备
		err = -ENODEV;
		if (dev_out == NULL)
			goto out;

		/* RACE: Check return value of inet_select_addr instead. */
		if (__in_dev_get_rtnl(dev_out) == NULL) {//检查in_device设备是否存在
			dev_put(dev_out);
			goto out;	/* Wrong error code */
		}

		if (ipv4_is_local_multicast(oldflp->fl4_dst) ||//如果目的地址是本机的组播地址
		    oldflp->fl4_dst == htonl(0xFFFFFFFF)) {//或者受限的广播地址
			if (!fl.fl4_src)//没有地址源地址，就根据发送设备选择一个地址。具体第三个参数scope范围，子网范围
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);
			goto make_route;
		}
		if (!fl.fl4_src) {// 如果还没有源地址，就调整范围查找源地址
			if (ipv4_is_multicast(oldflp->fl4_dst))//目标地址是组播地址
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      fl.fl4_scope);//路由键指定的范围
			else if (!oldflp->fl4_dst)//没有指定目标地址
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_HOST);//scope位本机范围
		}
	}

	if (!fl.fl4_dst) {//没有指定目的地址
		fl.fl4_dst = fl.fl4_src;//使用源地址作为目的地址
		if (!fl.fl4_dst)//目的地址和源地址都为空
			fl.fl4_dst = fl.fl4_src = htonl(INADDR_LOOPBACK);//使用环回地址
		if (dev_out)//如果有发送设备
			dev_put(dev_out);//递减发送设备引用计数
		dev_out = net->loopback_dev;//使用环回设备作为发送设备
		dev_hold(dev_out);//递增环回设备引用计数
		fl.oif = net->loopback_dev->ifindex;//路由兼职记录发送设备
		res.type = RTN_LOCAL;//记录本地类型
		flags |= RTCF_LOCAL;//增加本地路由标志位
		goto make_route;
	}

	if (fib_lookup(net, &fl, &res)) {//调用路由函数表根据路由键值查找
		res.fi = NULL;
		if (oldflp->oif) {
			/* Apparently, routing tables are wrong. Assume,
			   that the destination is on link.

			   WHY? DW.
			   Because we are allowed to send to iface
			   even if it has NO routes and NO assigned
			   addresses. When oif is specified, routing
			   tables are looked up with only one purpose:
			   to catch if destination is gatewayed, rather than
			   direct. Moreover, if MSG_DONTROUTE is set,
			   we send packet, ignoring both routing tables
			   and ifaddr state. --ANK


			   We could make it even if oif is unknown,
			   likely IPv6, but we do not.
			 */

			if (fl.fl4_src == 0)
				fl.fl4_src = inet_select_addr(dev_out, 0,
							      RT_SCOPE_LINK);//获取源地址
			res.type = RTN_UNICAST;
			goto make_route;
		}
		if (dev_out)

			dev_put(dev_out);
		err = -ENETUNREACH;
		goto out;
	}
	free_res = 1;

	if (res.type == RTN_LOCAL) {//路由时本地类型
		if (!fl.fl4_src)
			fl.fl4_src = fl.fl4_dst;
		if (dev_out)
			dev_put(dev_out);
		dev_out = net->loopback_dev;//设用环回设备
		dev_hold(dev_out);
		fl.oif = dev_out->ifindex;
		if (res.fi)
			fib_info_put(res.fi);
		res.fi = NULL;
		flags |= RTCF_LOCAL;
		goto make_route;
	}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
	if (res.fi->fib_nhs > 1 && fl.oif == 0)
		fib_select_multipath(&fl, &res);//多路径查询
	else
#endif
	if (!res.prefixlen && res.type == RTN_UNICAST && !fl.oif)//上面路由查询出掩码长度为0，且为单播地址且没有指定发送设备
		fib_select_default(net, &fl, &res);//查找路由信息

	if (!fl.fl4_src)
		fl.fl4_src = FIB_RES_PREFSRC(res);//使用路由中的源地址

	if (dev_out)
		dev_put(dev_out);
	dev_out = FIB_RES_DEV(res);//使用跳转结构中的设备作为发送设备
	dev_hold(dev_out);
	fl.oif = dev_out->ifindex;//记录发送设备号


make_route:
	//到达此处已经确定了源地址、目标地址和发送设备，接着创建路由表
	err = ip_mkroute_output(rp, &res, &fl, oldflp, dev_out, flags);


	if (free_res)
		fib_res_put(&res);//释放查询结果
	if (dev_out)
		dev_put(dev_out);//递减发送设备引用计数
out:	return err;
}

int __ip_route_output_key(struct net *net, struct rtable **rp,
			  const struct flowi *flp)
{
	unsigned hash;
	struct rtable *rth;

	hash = rt_hash(flp->fl4_dst, flp->fl4_src, flp->oif);//计算hash值

	rcu_read_lock_bh();
	//查找路由缓存表
	for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
		rth = rcu_dereference(rth->u.dst.rt_next)) {//沿着具体的缓存路由表队列进行查找
		if (rth->fl.fl4_dst == flp->fl4_dst &&//目的地址相同
		    rth->fl.fl4_src == flp->fl4_src && //源地址相同
		    rth->fl.iif == 0 && //没有指定入接口设备
		    rth->fl.oif == flp->oif && //发送网络设备相同
		    rth->fl.mark == flp->mark && //mark相同
		    !((rth->fl.fl4_tos ^ flp->fl4_tos) &
			    (IPTOS_RT_MASK | RTO_ONLINK)) &&
		    net_eq(dev_net(rth->u.dst.dev), net) && //命名空间相同
		    rth->rt_genid == atomic_read(&rt_genid)) {
			dst_use(&rth->u.dst, jiffies);//路由项记录使用时间，增加使用计数
			RT_CACHE_STAT_INC(out_hit);//递增路由缓存发送方向的命中计数
			rcu_read_unlock_bh();
			*rp = rth;//使上一级函数获得缓存路由表指针
			return 0;
		}
		RT_CACHE_STAT_INC(out_hlist_search);//递增路由缓存队列搜索的命中计数
	}
	rcu_read_unlock_bh();
	//缓存路由中没查询到，去路由中查询，并缓存在缓存路由表中
	return ip_route_output_slow(net, rp, flp);
}

EXPORT_SYMBOL_GPL(__ip_route_output_key);

static void ipv4_rt_blackhole_update_pmtu(struct dst_entry *dst, u32 mtu)
{
}

static struct dst_ops ipv4_dst_blackhole_ops = {
	.family			=	AF_INET,
	.protocol		=	__constant_htons(ETH_P_IP),
	.destroy		=	ipv4_dst_destroy,
	.check			=	ipv4_dst_check,
	.update_pmtu		=	ipv4_rt_blackhole_update_pmtu,
	.entry_size		=	sizeof(struct rtable),
	.entries		=	ATOMIC_INIT(0),
};


static int ipv4_dst_blackhole(struct rtable **rp, struct flowi *flp)
{
	struct rtable *ort = *rp;
	struct rtable *rt = (struct rtable *)
		dst_alloc(&ipv4_dst_blackhole_ops);

	if (rt) {
		struct dst_entry *new = &rt->u.dst;

		atomic_set(&new->__refcnt, 1);
		new->__use = 1;
		new->input = dst_discard;
		new->output = dst_discard;
		memcpy(new->metrics, ort->u.dst.metrics, RTAX_MAX*sizeof(u32));

		new->dev = ort->u.dst.dev;
		if (new->dev)
			dev_hold(new->dev);

		rt->fl = ort->fl;

		rt->idev = ort->idev;
		if (rt->idev)
			in_dev_hold(rt->idev);
		rt->rt_genid = atomic_read(&rt_genid);
		rt->rt_flags = ort->rt_flags;
		rt->rt_type = ort->rt_type;
		rt->rt_dst = ort->rt_dst;
		rt->rt_src = ort->rt_src;
		rt->rt_iif = ort->rt_iif;
		rt->rt_gateway = ort->rt_gateway;
		rt->rt_spec_dst = ort->rt_spec_dst;
		rt->peer = ort->peer;
		if (rt->peer)
			atomic_inc(&rt->peer->refcnt);

		dst_free(new);
	}

	dst_release(&(*rp)->u.dst);
	*rp = rt;
	return (rt ? 0 : -ENOMEM);
}

int ip_route_output_flow(struct net *net, struct rtable **rp, struct flowi *flp,
			 struct sock *sk, int flags)
{
	int err;

	if ((err = __ip_route_output_key(net, rp, flp)) != 0)//查找路由表
		return err;

	if (flp->proto) {//如果指定了协议
		if (!flp->fl4_src)//源地址位空
			flp->fl4_src = (*rp)->rt_src;//使用路由表的源地址
		if (!flp->fl4_dst)//目标地址为空
			flp->fl4_dst = (*rp)->rt_dst;//使用路由的表的目的地址
		err = __xfrm_lookup((struct dst_entry **)rp, flp, sk,
				    flags ? XFRM_LOOKUP_WAIT : 0);//通过XFRM调整路由项
		if (err == -EREMOTE)
			err = ipv4_dst_blackhole(rp, flp);//黑洞处理

		return err;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(ip_route_output_flow);

int ip_route_output_key(struct net *net, struct rtable **rp, struct flowi *flp)
{
	return ip_route_output_flow(net, rp, flp, NULL, 0);
}

static int rt_fill_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			int nowait, unsigned int flags)
{
	struct rtable *rt = skb->rtable;
	struct rtmsg *r;
	struct nlmsghdr *nlh;
	long expires;
	u32 id = 0, ts = 0, tsage = 0, error;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*r), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	r = nlmsg_data(nlh);
	r->rtm_family	 = AF_INET;
	r->rtm_dst_len	= 32;
	r->rtm_src_len	= 0;
	r->rtm_tos	= rt->fl.fl4_tos;
	r->rtm_table	= RT_TABLE_MAIN;
	NLA_PUT_U32(skb, RTA_TABLE, RT_TABLE_MAIN);
	r->rtm_type	= rt->rt_type;
	r->rtm_scope	= RT_SCOPE_UNIVERSE;
	r->rtm_protocol = RTPROT_UNSPEC;
	r->rtm_flags	= (rt->rt_flags & ~0xFFFF) | RTM_F_CLONED;
	if (rt->rt_flags & RTCF_NOTIFY)
		r->rtm_flags |= RTM_F_NOTIFY;

	NLA_PUT_BE32(skb, RTA_DST, rt->rt_dst);

	if (rt->fl.fl4_src) {
		r->rtm_src_len = 32;
		NLA_PUT_BE32(skb, RTA_SRC, rt->fl.fl4_src);
	}
	if (rt->u.dst.dev)
		NLA_PUT_U32(skb, RTA_OIF, rt->u.dst.dev->ifindex);
#ifdef CONFIG_NET_CLS_ROUTE
	if (rt->u.dst.tclassid)
		NLA_PUT_U32(skb, RTA_FLOW, rt->u.dst.tclassid);
#endif
	if (rt->fl.iif)
		NLA_PUT_BE32(skb, RTA_PREFSRC, rt->rt_spec_dst);
	else if (rt->rt_src != rt->fl.fl4_src)
		NLA_PUT_BE32(skb, RTA_PREFSRC, rt->rt_src);

	if (rt->rt_dst != rt->rt_gateway)
		NLA_PUT_BE32(skb, RTA_GATEWAY, rt->rt_gateway);

	if (rtnetlink_put_metrics(skb, rt->u.dst.metrics) < 0)
		goto nla_put_failure;

	error = rt->u.dst.error;
	expires = rt->u.dst.expires ? rt->u.dst.expires - jiffies : 0;
	if (rt->peer) {
		id = rt->peer->ip_id_count;
		if (rt->peer->tcp_ts_stamp) {
			ts = rt->peer->tcp_ts;
			tsage = get_seconds() - rt->peer->tcp_ts_stamp;
		}
	}

	if (rt->fl.iif) {
#ifdef CONFIG_IP_MROUTE
		__be32 dst = rt->rt_dst;

		if (ipv4_is_multicast(dst) && !ipv4_is_local_multicast(dst) &&
		    IPV4_DEVCONF_ALL(&init_net, MC_FORWARDING)) {
			int err = ipmr_get_route(skb, r, nowait);
			if (err <= 0) {
				if (!nowait) {
					if (err == 0)
						return 0;
					goto nla_put_failure;
				} else {
					if (err == -EMSGSIZE)
						goto nla_put_failure;
					error = err;
				}
			}
		} else
#endif
			NLA_PUT_U32(skb, RTA_IIF, rt->fl.iif);
	}

	if (rtnl_put_cacheinfo(skb, &rt->u.dst, id, ts, tsage,
			       expires, error) < 0)
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr* nlh, void *arg)
{
	struct net *net = sock_net(in_skb->sk);
	struct rtmsg *rtm;
	struct nlattr *tb[RTA_MAX+1];
	struct rtable *rt = NULL;
	__be32 dst = 0;
	__be32 src = 0;
	u32 iif;
	int err;
	struct sk_buff *skb;

	err = nlmsg_parse(nlh, sizeof(*rtm), tb, RTA_MAX, rtm_ipv4_policy);
	if (err < 0)
		goto errout;

	rtm = nlmsg_data(nlh);

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		err = -ENOBUFS;
		goto errout;
	}

	/* Reserve room for dummy headers, this skb can pass
	   through good chunk of routing engine.
	 */
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	/* Bugfix: need to give ip_route_input enough of an IP header to not gag. */
	ip_hdr(skb)->protocol = IPPROTO_ICMP;
	skb_reserve(skb, MAX_HEADER + sizeof(struct iphdr));

	src = tb[RTA_SRC] ? nla_get_be32(tb[RTA_SRC]) : 0;
	dst = tb[RTA_DST] ? nla_get_be32(tb[RTA_DST]) : 0;
	iif = tb[RTA_IIF] ? nla_get_u32(tb[RTA_IIF]) : 0;

	if (iif) {
		struct net_device *dev;

		dev = __dev_get_by_index(net, iif);
		if (dev == NULL) {
			err = -ENODEV;
			goto errout_free;
		}

		skb->protocol	= htons(ETH_P_IP);
		skb->dev	= dev;
		local_bh_disable();
		err = ip_route_input(skb, dst, src, rtm->rtm_tos, dev);
		local_bh_enable();

		rt = skb->rtable;
		if (err == 0 && rt->u.dst.error)
			err = -rt->u.dst.error;
	} else {
		struct flowi fl = {
			.nl_u = {
				.ip4_u = {
					.daddr = dst,
					.saddr = src,
					.tos = rtm->rtm_tos,
				},
			},
			.oif = tb[RTA_OIF] ? nla_get_u32(tb[RTA_OIF]) : 0,
		};
		err = ip_route_output_key(net, &rt, &fl);
	}

	if (err)
		goto errout_free;

	skb->rtable = rt;
	if (rtm->rtm_flags & RTM_F_NOTIFY)
		rt->rt_flags |= RTCF_NOTIFY;

	err = rt_fill_info(skb, NETLINK_CB(in_skb).pid, nlh->nlmsg_seq,
			   RTM_NEWROUTE, 0, 0);
	if (err <= 0)
		goto errout_free;

	err = rtnl_unicast(skb, net, NETLINK_CB(in_skb).pid);
errout:
	return err;

errout_free:
	kfree_skb(skb);
	goto errout;
}

int ip_rt_dump(struct sk_buff *skb,  struct netlink_callback *cb)
{
	struct rtable *rt;
	int h, s_h;
	int idx, s_idx;
	struct net *net;

	net = sock_net(skb->sk);

	s_h = cb->args[0];
	if (s_h < 0)
		s_h = 0;
	s_idx = idx = cb->args[1];
	for (h = s_h; h <= rt_hash_mask; h++) {
		rcu_read_lock_bh();
		for (rt = rcu_dereference(rt_hash_table[h].chain), idx = 0; rt;
		     rt = rcu_dereference(rt->u.dst.rt_next), idx++) {
			if (!net_eq(dev_net(rt->u.dst.dev), net) || idx < s_idx)
				continue;
			if (rt->rt_genid != atomic_read(&rt_genid))
				continue;
			skb->dst = dst_clone(&rt->u.dst);
			if (rt_fill_info(skb, NETLINK_CB(cb->skb).pid,
					 cb->nlh->nlmsg_seq, RTM_NEWROUTE,
					 1, NLM_F_MULTI) <= 0) {
				dst_release(xchg(&skb->dst, NULL));
				rcu_read_unlock_bh();
				goto done;
			}
			dst_release(xchg(&skb->dst, NULL));
		}
		rcu_read_unlock_bh();
		s_idx = 0;
	}

done:
	cb->args[0] = h;
	cb->args[1] = idx;
	return skb->len;
}

void ip_rt_multicast_event(struct in_device *in_dev)
{
	rt_cache_flush(0);
}

#ifdef CONFIG_SYSCTL
static int flush_delay;

static int ipv4_sysctl_rtcache_flush(ctl_table *ctl, int write,
					struct file *filp, void __user *buffer,
					size_t *lenp, loff_t *ppos)
{
	if (write) {
		proc_dointvec(ctl, write, filp, buffer, lenp, ppos);
		rt_cache_flush(flush_delay);
		return 0;
	}

	return -EINVAL;
}

static int ipv4_sysctl_rtcache_flush_strategy(ctl_table *table,
						int __user *name,
						int nlen,
						void __user *oldval,
						size_t __user *oldlenp,
						void __user *newval,
						size_t newlen)
{
	int delay;
	if (newlen != sizeof(int))
		return -EINVAL;
	if (get_user(delay, (int __user *)newval))
		return -EFAULT;
	rt_cache_flush(delay);
	return 0;
}

ctl_table ipv4_route_table[] = {
	{
		.ctl_name 	= NET_IPV4_ROUTE_FLUSH,
		.procname	= "flush",
		.data		= &flush_delay,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= &ipv4_sysctl_rtcache_flush,
		.strategy	= &ipv4_sysctl_rtcache_flush_strategy,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_THRESH,
		.procname	= "gc_thresh",
		.data		= &ipv4_dst_ops.gc_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MAX_SIZE,
		.procname	= "max_size",
		.data		= &ip_rt_max_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		/*  Deprecated. Use gc_min_interval_ms */

		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL,
		.procname	= "gc_min_interval",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS,
		.procname	= "gc_min_interval_ms",
		.data		= &ip_rt_gc_min_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_ms_jiffies,
		.strategy	= &sysctl_ms_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_TIMEOUT,
		.procname	= "gc_timeout",
		.data		= &ip_rt_gc_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_INTERVAL,
		.procname	= "gc_interval",
		.data		= &ip_rt_gc_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_LOAD,
		.procname	= "redirect_load",
		.data		= &ip_rt_redirect_load,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_NUMBER,
		.procname	= "redirect_number",
		.data		= &ip_rt_redirect_number,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_REDIRECT_SILENCE,
		.procname	= "redirect_silence",
		.data		= &ip_rt_redirect_silence,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_COST,
		.procname	= "error_cost",
		.data		= &ip_rt_error_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_ERROR_BURST,
		.procname	= "error_burst",
		.data		= &ip_rt_error_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_GC_ELASTICITY,
		.procname	= "gc_elasticity",
		.data		= &ip_rt_gc_elasticity,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MTU_EXPIRES,
		.procname	= "mtu_expires",
		.data		= &ip_rt_mtu_expires,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_PMTU,
		.procname	= "min_pmtu",
		.data		= &ip_rt_min_pmtu,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_MIN_ADVMSS,
		.procname	= "min_adv_mss",
		.data		= &ip_rt_min_advmss,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_IPV4_ROUTE_SECRET_INTERVAL,
		.procname	= "secret_interval",
		.data		= &ip_rt_secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{ .ctl_name = 0 }
};
#endif

#ifdef CONFIG_NET_CLS_ROUTE
struct ip_rt_acct *ip_rt_acct __read_mostly;
#endif /* CONFIG_NET_CLS_ROUTE */
//路由缓存大小
static __initdata unsigned long rhash_entries;
static int __init set_rhash_entries(char *str)
{
	if (!str)
		return 0;
	rhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("rhash_entries=", set_rhash_entries);

int __init ip_rt_init(void)
{
	int rc = 0;
	//设置路由随机数
	atomic_set(&rt_genid, (int) ((num_physpages ^ (num_physpages>>8)) ^
			     (jiffies ^ (jiffies >> 7))));

#ifdef CONFIG_NET_CLS_ROUTE
	ip_rt_acct = __alloc_percpu(256 * sizeof(struct ip_rt_acct));
	if (!ip_rt_acct)
		panic("IP: failed to allocate ip_rt_acct\n");
#endif
	//路由缓存内存池
	ipv4_dst_ops.kmem_cachep =
		kmem_cache_create("ip_dst_cache", sizeof(struct rtable), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	ipv4_dst_blackhole_ops.kmem_cachep = ipv4_dst_ops.kmem_cachep;
	//建立路由缓存hash表
	rt_hash_table = (struct rt_hash_bucket *)
		alloc_large_system_hash("IP route cache",
					sizeof(struct rt_hash_bucket),
					rhash_entries,
					(num_physpages >= 128 * 1024) ?
					15 : 17,
					0,
					&rt_hash_log,
					&rt_hash_mask,
					0);
	//初始化路由缓存hash表
	memset(rt_hash_table, 0, (rt_hash_mask + 1) * sizeof(struct rt_hash_bucket));
	rt_hash_lock_init();
	//设置gc时间和缓存最大数量
	ipv4_dst_ops.gc_thresh = (rt_hash_mask + 1);
	ip_rt_max_size = (rt_hash_mask + 1) * 16;
	//网卡相关的通知连(网卡的注册、up、down事件处理)，注册ip address相关命令处理函数
	devinet_init();
	//注册通知链和创建alias缓存，注册ip route 处理函数
	ip_fib_init();
	//定时对缓冲进行冲刷
	rt_secret_timer.function = rt_secret_rebuild;
	rt_secret_timer.data = 0;
	init_timer_deferrable(&rt_secret_timer);

	/* All the timers, started at system startup tend
	   to synchronize. Perturb it a bit.
	 */
	//注册gc任务
	schedule_delayed_work(&expires_work,
		net_random() % ip_rt_gc_interval + ip_rt_gc_interval);

	rt_secret_timer.expires = jiffies + net_random() % ip_rt_secret_interval +
		ip_rt_secret_interval;
	add_timer(&rt_secret_timer);

	if (ip_rt_proc_init())//向网络命名空间下的/proc文件系统注册rt_cache
		printk(KERN_ERR "Unable to create route proc files\n");
#ifdef CONFIG_XFRM
	xfrm_init();
	xfrm4_init();
#endif
	//注册netlink消息
	rtnl_register(PF_INET, RTM_GETROUTE, inet_rtm_getroute, NULL);//ip route get命令处理

	return rc;
}

EXPORT_SYMBOL(__ip_select_ident);
EXPORT_SYMBOL(ip_route_input);
EXPORT_SYMBOL(ip_route_output_key);
