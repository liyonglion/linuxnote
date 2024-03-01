#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <net/rtnetlink.h>

/*
 * NUD stands for "neighbor unreachability detection"
 */
/*
对于NUD_IN_TIMER，通过名称我们就知道，当邻居项处于该状态时，则会启动定时器。下面我们一一分析这几个邻居项状态，通过分
析完这几个状态，我们就基本上会理解邻居项状态机中定时器处理函数neigh timer handler() 的设计逻辑了。
*/
#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
/*
在领居协议的基本状态中，处于NUD_REACHABLE、NUD_PROBE、NUD_STALE、NUD_DELAY状态时，数据包是可以正常发送的只是发送的函数不同。
这样就不难理解NUD_VALID包含NUD_PERMANENT、NUD_NOARP、NUD_REACHABLE、NUD_PROBENUD 、NUD_STALE、NUD_DELAY了
*/
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
/*
主要是表示邻居是可达的状态，对于NUD_PERMANENT、NUD_NOARP状态的邻居项，其邻居状态是不会改变的，一直是有效的，除
非删除该邻居项。
*/
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

struct neigh_parms//代表的是邻居协议在每个设备上的不同参数
{
#ifdef CONFIG_NET_NS
	struct net *net; //所属网络
#endif
	struct net_device *dev;//所属设备
	struct neigh_parms *next;//因为一个设备可以配置多个不同的邻居协议，所以会有多个neigh_parms
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
	struct neigh_table *tbl;

	void	*sysctl_table;

	int dead;
	atomic_t refcnt;
	struct rcu_head rcu_head;

	int	base_reachable_time;//reachable 有效时，arp默认为30s
	int	retrans_time;//solicit请求报文重发间隔时。arp默认为1s
	int	gc_staletime; //闲置时间。arp默认为300s
	int	reachable_time;//确认有效时间超时长，，这个值默认为30s
	int	delay_probe_time;//probe延迟时间。arp默认为5s

	int	queue_len; //arp队列长度
	int	ucast_probes; //再NUD_PROBE状态下，最大发送arp报文次数
	int	app_probes;//APP最大探测次数
	int	mcast_probes;//组播探测最大次数
	int	anycast_delay;
	int	proxy_delay;
	int	proxy_qlen;
	int	locktime;
};

struct neigh_statistics
{
	unsigned long allocs;		/* number of allocated neighs */
	unsigned long destroys;		/* number of destroyed neighs */
	unsigned long hash_grows;	/* number of hash resizes */

	unsigned long res_failed;	/* nomber of failed resolutions */

	unsigned long lookups;		/* number of lookups */
	unsigned long hits;		/* number of hits (among lookups) */

	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

struct neighbour
{
	struct neighbour	*next;//指向下一个邻居的指针
	struct neigh_table	*tbl;//所属的邻居表结构
	struct neigh_parms	*parms; //邻居参数结，用in_dev->arp_param进行赋值
	struct net_device		*dev; //网络设备指针，这个设备指的是配置primary_key中IP地址的设备。
	unsigned long		used; //邻居结构使用时间
	unsigned long		confirmed; //NUD_CONNECTED时间
	unsigned long		updated;//状态更新时间
	__u8			flags; //标志位
	__u8			nud_state;//状态标志
	__u8			type;//记录primary_key中IP地址类型，是RTN_BROADCAST、RTN_UNICAST还是RTN_MULTICAST、RTN_LOCAL
	__u8			dead; //删除标志
	atomic_t		probes; //记录邻居发送的solicit请求次数
	rwlock_t		lock;//读写锁
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];//学习到的MAC地址
	//TODO： 为什么这个地方为什么需要使用链表？
	struct hh_cache		*hh;//链路层头部缓存，加速发送。
	atomic_t		refcnt;//使用计数器
	int			(*output)(struct sk_buff *skb);//发送函数指针
	struct sk_buff_head	arp_queue;//需要处理的数据包队列。当没有学习到MAC地址时，将数据包放入该队列，等待学习到MAC地址后，再发送数据包
	struct timer_list	timer;//定时器队列，用于定时发送arp报文以及超时重传arp报文
	struct neigh_ops	*ops;//操作函数表
	u8			primary_key[0];//主键值，一般是网关地址,即IP地址
};

struct neigh_ops
{
	int			family;//协议。arp情况下为AF_INET
	void			(*solicit)(struct neighbour *, struct sk_buff*);//发送邻居请求的函数指。。
	void			(*error_report)(struct neighbour *, struct sk_buff*);//当有效数据要发送，而邻居不可，则调用该函数向三层发送错误信息
	int			(*output)(struct sk_buff*);//输出函数
	int			(*connected_output)(struct sk_buff*);//当邻居可达时，使用该函数进行发送数据包
	int			(*hh_output)(struct sk_buff*);
	int			(*queue_xmit)(struct sk_buff*);
};

struct pneigh_entry
{
	struct pneigh_entry	*next;
#ifdef CONFIG_NET_NS
	struct net		*net;
#endif
	struct net_device	*dev;
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */


struct neigh_table
{
	struct neigh_table	*next;//指向队列中的下一个邻居表
	int			family;//协议族
	int			entry_size;//邻居结构的总长度，邻居结构的最后要放一个IP地址作为hash值
	int			key_len;//IP地址长度
	__u32			(*hash)(const void *pkey, const struct net_device *);//hash函数
	int			(*constructor)(struct neighbour *);//neighbour结构的创建函数指针
	int			(*pconstructor)(struct pneigh_entry *);//IPv6 pneigh_entry结构的创建函数指针
	void			(*pdestructor)(struct pneigh_entry *);//IPv6 pneigh_entry结构的销毁函数指针
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id;
	struct neigh_parms	parms;//邻居参数结构
	/* HACK. gc_* shoul follow parms without a gap! */
	int			gc_interval;//回收间隔时间
	int			gc_thresh1;//回收最小阈值
	int			gc_thresh2;//回收中等阈值
	int			gc_thresh3;//回收最大阈值
	unsigned long		last_flush;//最近一次回收时间
	struct timer_list 	gc_timer;//回收定时器
	struct timer_list 	proxy_timer;//代理定时器
	struct sk_buff_head	proxy_queue;//代理队列
	atomic_t		entries;//邻居结构数量
	rwlock_t		lock; //读写锁
	unsigned long		last_rand;//最近更新时间
	struct kmem_cache		*kmem_cachep;//用于分配邻居结构的缓存
	struct neigh_statistics	*stats;//邻居统计结构
	struct neighbour	**hash_buckets;//邻居结构hash桶
	unsigned int		hash_mask;//hash桶数量
	__u32			hash_rnd;//哈希值
	unsigned int		hash_chain_gc;//下一个要搜索的hahs值队列
	struct pneigh_entry	**phash_buckets;//保存IP地址的队列
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*pde;//proc文件系统
#endif
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   struct net *net,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);

static inline
struct net			*neigh_parms_net(const struct neigh_parms *parms)
{
#ifdef CONFIG_NET_NS
	return parms->net;
#else
	return &init_net;
#endif
}

extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev, int creat);
extern struct pneigh_entry	*__pneigh_lookup(struct neigh_table *tbl,
						 struct net *net,
						 const void *key,
						 struct net_device *dev);
extern int			pneigh_delete(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev);

static inline
struct net			*pneigh_net(const struct pneigh_entry *pneigh)
{
#ifdef CONFIG_NET_NS
	return pneigh->net;
#else
	return &init_net;
#endif
}

extern void neigh_app_ns(struct neighbour *n);
extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler,
						      ctl_handler *strategy);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;//保存邻居使用时间
	//检查邻居状态不处于链接、延迟、探测状态，则发送arp报文。处于这几个状态时可以直接发送数据包，而不用发送arp报文。
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
