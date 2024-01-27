/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 FIB: lookup engine and maintenance routines.
 *
 * Version:	$Id: fib_hash.c,v 1.13 2001/10/31 21:55:54 davem Exp $
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
#include <linux/netlink.h>
#include <linux/init.h>

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/ip_fib.h>

#include "fib_lookup.h"

static struct kmem_cache *fn_hash_kmem __read_mostly;
static struct kmem_cache *fn_alias_kmem __read_mostly;

struct fib_node {//路由节点结构体( 子网相等的路由被分在一起 )
	struct hlist_node	fn_hash;// 链接到hash表节点( 注意到我们上面所说的fn_zone中的fz_hash了吗？fz_hash哈希之后得到的结果就是fib_node的这个字段，所以这个字段同样仅仅是作为链接作用而已 )
	/* 别名？其实更好的理解是这样的：虽然现在所有的路由都是同一个子网了，但是路由之间还会有其他的信息不同例如tos。
	fn_alias是一个链表，按tos从大到小排列，这样可以快速的找到一个目的地址对应的路由。*/
	struct list_head	fn_alias;
	__be32			fn_key;// 计算出来的hash key:目的地址&子网掩码
	struct fib_alias        fn_embedded_alias;// 分配路由节点的时候同时也分配一个路由别名，所以称为嵌入式的。因为大部分fib_node下只有一个路由别名，为了避免内存碎片，这里提嵌入一个对象。
};
//路由区定义：fn_zone，举个例子，子网掩码长度相同的认为是相同的路由区
struct fn_zone {// 路由区结构体(所有的子网长度相等的被分在同一个路由区)
	struct fn_zone		*fz_next;	/*  指向下一个不为空的路由区结构，那么所有的路由区就能链接起来	*/

	/*用一个hash数组，用来hash得到一个hlist_head，是很多的fib_node通过自己的字段连接在这个队列中，
	那么通过这个fz_hahs字段可以找到fib_node所在的队列的头hlist_head，进而找到对应的fib_node ( 注意：上面说的hash数组的长度是fz_divisor长度)*/
	struct hlist_head	*fz_hash;	/* Hash table pointer	*/
	int			fz_nent;	/*  包含的路由节总数	*/

	int			fz_divisor;	/* hash头数量(上面说了)		*/
	u32			fz_hashmask;	/* (fz_divisor - 1)确定hash头的掩码	*/
#define FZ_HASHMASK(fz)		((fz)->fz_hashmask)

	int			fz_order;	/* Zone order	子网掩码位数	*/
	__be32			fz_mask; //子网掩码
#define FZ_MASK(fz)		((fz)->fz_mask) //获取子网掩码的宏定义
};

/* NOTE. On fast computers evaluation of fz_hashmask and fz_mask
 * can be cheaper than memory lookup, so that FZ_* macros are used.
 */

struct fn_hash {// 路由区结构体的数组( 包含所有的额路由区的情况 )
	// 路由区分成33份，why？仔细想想，子网掩码长度是1~32，0长度掩码代表网关，那么加起来就是33，
	//即：fn_zone[0]的掩码是0.0.0.0，fn_zone[1]是10000000.00000000.00000000.0000000这一类  等等
	struct fn_zone	*fn_zones[33];
	struct fn_zone	*fn_zone_list;// 指向第一个活动的路由区；将fn_zones按照降序（路由最长掩码匹配）串起来，注意有点fn_zones元素有可能为空
};

static inline u32 fn_hash(__be32 key, struct fn_zone *fz)
{
	u32 h = ntohl(key)>>(32 - fz->fz_order);
	h ^= (h>>20);
	h ^= (h>>10);
	h ^= (h>>5);
	h &= FZ_HASHMASK(fz);
	return h;
}

static inline __be32 fz_key(__be32 dst, struct fn_zone *fz)
{
	return dst & FZ_MASK(fz);
}

static DEFINE_RWLOCK(fib_hash_lock);
static unsigned int fib_hash_genid;

#define FZ_MAX_DIVISOR ((PAGE_SIZE<<MAX_ORDER) / sizeof(struct hlist_head))

static struct hlist_head *fz_hash_alloc(int divisor)
{
	unsigned long size = divisor * sizeof(struct hlist_head);

	if (size <= PAGE_SIZE) {
		return kzalloc(size, GFP_KERNEL);
	} else {
		return (struct hlist_head *)
			__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));
	}
}

/* The fib hash lock must be held when this is called. */
static inline void fn_rebuild_zone(struct fn_zone *fz,
				   struct hlist_head *old_ht,
				   int old_divisor)
{
	int i;

	for (i = 0; i < old_divisor; i++) {
		struct hlist_node *node, *n;
		struct fib_node *f;

		hlist_for_each_entry_safe(f, node, n, &old_ht[i], fn_hash) {
			struct hlist_head *new_head;

			hlist_del(&f->fn_hash);

			new_head = &fz->fz_hash[fn_hash(f->fn_key, fz)];
			hlist_add_head(&f->fn_hash, new_head);
		}
	}
}

static void fz_hash_free(struct hlist_head *hash, int divisor)
{
	unsigned long size = divisor * sizeof(struct hlist_head);

	if (size <= PAGE_SIZE)
		kfree(hash);
	else
		free_pages((unsigned long)hash, get_order(size));
}

static void fn_rehash_zone(struct fn_zone *fz)
{
	struct hlist_head *ht, *old_ht;
	int old_divisor, new_divisor;
	u32 new_hashmask;

	old_divisor = fz->fz_divisor;

	switch (old_divisor) {
	case 16:
		new_divisor = 256;
		break;
	case 256:
		new_divisor = 1024;
		break;
	default:
		if ((old_divisor << 1) > FZ_MAX_DIVISOR) {
			printk(KERN_CRIT "route.c: bad divisor %d!\n", old_divisor);
			return;
		}
		new_divisor = (old_divisor << 1);
		break;
	}

	new_hashmask = (new_divisor - 1);

#if RT_CACHE_DEBUG >= 2
	printk(KERN_DEBUG "fn_rehash_zone: hash for zone %d grows from %d\n",
	       fz->fz_order, old_divisor);
#endif

	ht = fz_hash_alloc(new_divisor);

	if (ht)	{
		write_lock_bh(&fib_hash_lock);
		old_ht = fz->fz_hash;
		fz->fz_hash = ht;
		fz->fz_hashmask = new_hashmask;
		fz->fz_divisor = new_divisor;
		fn_rebuild_zone(fz, old_ht, old_divisor);
		fib_hash_genid++;
		write_unlock_bh(&fib_hash_lock);

		fz_hash_free(old_ht, old_divisor);
	}
}

static inline void fn_free_node(struct fib_node * f)
{
	kmem_cache_free(fn_hash_kmem, f);
}

static inline void fn_free_alias(struct fib_alias *fa, struct fib_node *f)
{
	fib_release_info(fa->fa_info);
	if (fa == &f->fn_embedded_alias)
		fa->fa_info = NULL;
	else
		kmem_cache_free(fn_alias_kmem, fa);
}

static struct fn_zone *
fn_new_zone(struct fn_hash *table, int z)
{
	int i;
	struct fn_zone *fz = kzalloc(sizeof(struct fn_zone), GFP_KERNEL);
	if (!fz)
		return NULL;
	//z 表示的是掩码，如果z是0，则是该路由表默认路由项。
	if (z) {
		fz->fz_divisor = 16;//hash表的大小是16
	} else {
		fz->fz_divisor = 1;
	}
	fz->fz_hashmask = (fz->fz_divisor - 1);//hash掩码
	fz->fz_hash = fz_hash_alloc(fz->fz_divisor);//申请一个hash表数组
	if (!fz->fz_hash) {
		kfree(fz);
		return NULL;
	}
	fz->fz_order = z;//保存子网掩码位数
	fz->fz_mask = inet_make_mask(z);//保存子网掩码

	/* Find the first not empty zone with more specific mask */
	for (i=z+1; i<=32; i++)
		if (table->fn_zones[i])
			break;
	write_lock_bh(&fib_hash_lock);
	//放入到fn_zone_list中合适位置。
	if (i>32) {
		/* No more specific masks, we are the first. */
		fz->fz_next = table->fn_zone_list;
		table->fn_zone_list = fz;
	} else {
		fz->fz_next = table->fn_zones[i]->fz_next;
		table->fn_zones[i]->fz_next = fz;
	}
	table->fn_zones[z] = fz;
	fib_hash_genid++;
	write_unlock_bh(&fib_hash_lock);
	return fz;
}

static int
fn_hash_lookup(struct fib_table *tb, const struct flowi *flp, struct fib_result *res)
{
	int err;
	struct fn_zone *fz;
	struct fn_hash *t = (struct fn_hash*)tb->tb_data;

	read_lock(&fib_hash_lock);
	//fn_zone_list是按子网掩码位数降序排列的,所以这里的匹配是按照子网掩码从高到底遍历，也是路由器按照最长掩码匹配
	for (fz = t->fn_zone_list; fz; fz = fz->fz_next) {
		struct hlist_head *head;
		struct hlist_node *node;
		struct fib_node *f;
		__be32 k = fz_key(flp->fl4_dst, fz);//目标IP和掩码进行&操作即为KEY

		head = &fz->fz_hash[fn_hash(k, fz)];//从fib_node中开始查找，fib_node中保存的是目标前缀一致，但是TOS、priority、scope不一致的fib_alias路由项
		hlist_for_each_entry(f, node, head, fn_hash) {
			if (f->fn_key != k)//f->fn_key 是路由项的目的地址&掩码，k是flp->fl4_dst(需要查询的IP)&掩码，不一致说明路由项的目的地址和flp->fl4_dst不匹配
				continue;
			//路由前缀一样，则进入更加深层的去判断fib_alias。
			err = fib_semantic_match(&f->fn_alias,
						 flp, res,
						 f->fn_key, fz->fz_mask,
						 fz->fz_order);
			if (err <= 0)
				goto out;
		}
	}
	err = 1;
out:
	read_unlock(&fib_hash_lock);
	return err;
}
/*
假设有多个默认路由项，fib_lookup()返回第一个匹配(tos值相等，flp->scope值大于路由项的scope)的默认路由项,极有可能还有更合适的路由项；
我们把fib_lookup()返回的路由项叫旧路由项，最优路由项叫新路由项
*/
static void
fn_hash_select_default(struct fib_table *tb, const struct flowi *flp, struct fib_result *res)
{
	int order, last_idx;
	struct hlist_node *node;
	struct fib_node *f;
	struct fib_info *fi = NULL;
	struct fib_info *last_resort;
	struct fn_hash *t = (struct fn_hash*)tb->tb_data;//获取fn_hash
	struct fn_zone *fz = t->fn_zones[0];//掩码为0，说明是默认路由项

	if (fz == NULL)
		return;

	last_idx = -1;
	last_resort = NULL;
	order = -1;

	read_lock(&fib_hash_lock);
	//遍历路由节点队列。因为默认的掩码为0，所以查找的hash key一定是0，也就是只有一个fib_node
	hlist_for_each_entry(f, node, &fz->fz_hash[0], fn_hash) {
		struct fib_alias *fa;
		//遍历路由别名队列。注意：查询的时候直接跳过了TOS的判断
		list_for_each_entry(fa, &f->fn_alias, fa_list) {
			struct fib_info *next_fi = fa->fa_info;

			if (fa->fa_scope != res->scope || //新老路由项的scope值必须一样，一般默认路由的scope为RT_SCOPE_UNIVERSE；为什么新路由项scope不能大于旧路由项scope值？这样匹配的网络范围更小，更优吗？
			    fa->fa_type != RTN_UNICAST)//默认路由项必须是单播
				continue;

			if (next_fi->fib_priority > res->fi->fib_priority)//新路由项优先级不能低于旧路由先优先级
				break;
			if (!next_fi->fib_nh[0].nh_gw ||// 第一个下一跳网关为空
			    next_fi->fib_nh[0].nh_scope != RT_SCOPE_LINK)//检查路由信息中跳转结构
				continue;
			fa->fa_state |= FA_S_ACCESSED;//设置路由别名访问标志

			if (fi == NULL) {
				if (next_fi != res->fi)//找到的路由信息与查找的不同
					break;
			} else if (!fib_detect_death(fi, order, &last_resort,
						&last_idx, tb->tb_default)) {//在邻居子系统中检测是否可以到达
				fib_result_assign(res, fi);//记录查找到的路由信息结构
				tb->tb_default = order;//记录路由信息结构在队列中的序号
				goto out;
			}
			fi = next_fi;//找到更优的路由信息结构
			order++;
		}
	}

	if (order <= 0 || fi == NULL) {//如果没有找到路由信息结构
		tb->tb_default = -1;//将路由信息的队列序号设为负值
		goto out;
	}

	if (!fib_detect_death(fi, order, &last_resort, &last_idx,
				tb->tb_default)) {//在邻居子系统中检测路由是否可以到达
		fib_result_assign(res, fi);//将路由信息结构记录到查询结果中
		tb->tb_default = order;//将路由信息结构的队列序号记录到路由函数表中
		goto out;
	}

	if (last_idx >= 0)
		fib_result_assign(res, last_resort);//将最后认定的路由信息结构记录到结果中
	tb->tb_default = last_idx;//将最后认定的队列序号记录到路由函数表
out:
	read_unlock(&fib_hash_lock);
}

/* Insert node F to FZ. */
static inline void fib_insert_node(struct fn_zone *fz, struct fib_node *f)
{
	struct hlist_head *head = &fz->fz_hash[fn_hash(f->fn_key, fz)];

	hlist_add_head(&f->fn_hash, head);
}

/* Return the node in FZ matching KEY. */
//根据搜索关键字(dst_addr & mask)，在fn_zone变量fz中查找符合条件的fib_node变量
static struct fib_node *fib_find_node(struct fn_zone *fz, __be32 key)
{
	struct hlist_head *head = &fz->fz_hash[fn_hash(key, fz)];
	struct hlist_node *node;
	struct fib_node *f;

	hlist_for_each_entry(f, node, head, fn_hash) {
		if (f->fn_key == key)//判断是否匹配
			return f;
	}

	return NULL;
}
/*
1. 通过掩码长度找到对应的fib_zone
2. 通过目标地址和掩码，查找对应的fib_node
3. 通过TOS、prority 模糊匹配到对应的fib_alias
4. 继续遍历，是否可以精确匹配到路由别名。这里的精确包含所有的信息：scope、type、protocol、nh、mss、mtu等
5. 存在重复路由项，指定了replace则替换，否则返回
6. 不存在情况下，创建fib_alias，并关联fib_info，插入到fib_node链表中的合适位置
*/
static int fn_hash_insert(struct fib_table *tb, struct fib_config *cfg)
{
	struct fn_hash *table = (struct fn_hash *) tb->tb_data;
	struct fib_node *new_f = NULL;
	struct fib_node *f;
	struct fib_alias *fa, *new_fa;
	struct fn_zone *fz;
	struct fib_info *fi;
	u8 tos = cfg->fc_tos;
	__be32 key;
	int err;
	//掩码长度大于32，错误
	if (cfg->fc_dst_len > 32)
		return -EINVAL;
	//根据掩码，找到对应的zone。
	fz = table->fn_zones[cfg->fc_dst_len];
	if (!fz && !(fz = fn_new_zone(table, cfg->fc_dst_len)))//不存在，则创建fn_zone
		return -ENOBUFS;

	key = 0;
	if (cfg->fc_dst) {
		if (cfg->fc_dst & ~FZ_MASK(fz))
			return -EINVAL;
		key = fz_key(cfg->fc_dst, fz);//将目标地址和掩码进行&操作，计算得到key
	}
	//创建fib_info，也就是路由项。如果存在一样的路由项，则返回老的路由项fib_info对象
	fi = fib_create_info(cfg);
	if (IS_ERR(fi))
		return PTR_ERR(fi);

	if (fz->fz_nent > (fz->fz_divisor<<1) &&
	    fz->fz_divisor < FZ_MAX_DIVISOR &&
	    (cfg->fc_dst_len == 32 ||
	     (1 << cfg->fc_dst_len) > fz->fz_divisor))
		fn_rehash_zone(fz);
	//查找fib_node。fib_node中存放的是具有相同子网的路由项，子网相同(也就是说fib_node中存放的是路由前缀相同的路由项)，但tos、优先级、type、scope不一样，所以下一步需要继续遍历fib_alias。
	f = fib_find_node(fz, key);
	//遍历fib_node中fib_alias链表
	if (!f)//不存在fib_node，肯定不存在fib_alias，后面会new一个fib_node和fib_alias
		fa = NULL;
	else
		fa = fib_find_alias(&f->fn_alias, tos, fi->fib_priority);//模糊匹配：找到首个比tos小，且优先级大于或等于prio的路由表别名。

	/* Now fa, if non-NULL, points to the first fib alias
	 * with the same keys [prefix,tos,priority], if such key already
	 * exists or to the node before which we will insert new one.
	 *
	 * If fa is NULL, we will need to allocate a new one and
	 * insert to the head of f.
	 *
	 * If f is NULL, no fib node matched the destination key
	 * and we need to allocate a new one of those as well.
	 */
	//存在相同tos、priority的路由项，但是还要继续匹配scope、type 是否也相同，避免插入重复的路由项，需要精确匹配
	if (fa && fa->fa_tos == tos &&
	    fa->fa_info->fib_priority == fi->fib_priority) {
		struct fib_alias *fa_first, *fa_match;

		err = -EEXIST;
		if (cfg->fc_nlflags & NLM_F_EXCL)//不允许修改，直接返回
			goto out;

		/* We have 2 goals:
		 * 1. Find exact match for type, scope, fib_info to avoid
		 * duplicate routes
		 * 2. Find next 'fa' (or head), NLM_F_APPEND inserts before it
		 */
		fa_match = NULL;//完全匹配的fib_alias
		fa_first = fa;//暂时保存模糊匹配。所以模糊匹配的项包括：目的地址&掩码、tos、priority
		//判断是否会出现一模一样的路由项，也就是精确的匹配
		fa = list_entry(fa->fa_list.prev, struct fib_alias, fa_list);
		list_for_each_entry_continue(fa, &f->fn_alias, fa_list) {
			if (fa->fa_tos != tos)
				break;
			if (fa->fa_info->fib_priority != fi->fib_priority)
				break;
			if (fa->fa_type == cfg->fc_type &&
			    fa->fa_scope == cfg->fc_scope &&
			    fa->fa_info == fi) {// 路由项的tos、priority、type 、scope	和 fib_info(所有的信息完全一样) 一致，就跳出
				fa_match = fa;
				break;
			}
		}
		//替换旧的fib_info，精确匹配是所有信息都一样，没有必要替换，所以直接goto out
		if (cfg->fc_nlflags & NLM_F_REPLACE) {
			struct fib_info *fi_drop;
			u8 state;

			fa = fa_first;//模糊匹配的fib_alias
			if (fa_match) {//找到一模一样的路由项，直接返回
				if (fa == fa_match)
					err = 0;
				goto out;
			}
			//走到该位置，说明没有找到一模一样的fib_aiias，需要替换模糊匹配的fib_alias中fa_info、type、scope
			write_lock_bh(&fib_hash_lock);
			fi_drop = fa->fa_info;
			fa->fa_info = fi;
			fa->fa_type = cfg->fc_type;
			fa->fa_scope = cfg->fc_scope;
			state = fa->fa_state;
			fa->fa_state &= ~FA_S_ACCESSED;
			fib_hash_genid++;
			write_unlock_bh(&fib_hash_lock);

			fib_release_info(fi_drop);//释放旧的fib_info
			if (state & FA_S_ACCESSED)
				rt_cache_flush(-1);//刷新缓存路由
			rtmsg_fib(RTM_NEWROUTE, key, fa, cfg->fc_dst_len, tb->tb_id,
				  &cfg->fc_nlinfo, NLM_F_REPLACE);//向netlink发送消息，通知用户空间
			return 0;
		}

		/* Error if we find a perfect match which
		 * uses the same scope, type, and nexthop
		 * information.
		 */
		if (fa_match)
			goto out;

		if (!(cfg->fc_nlflags & NLM_F_APPEND))
			fa = fa_first;
	}
	//找不到相同的fib_alias,需要创建新的fib_alias
	err = -ENOENT;
	if (!(cfg->fc_nlflags & NLM_F_CREATE))//不允许创建，直接返回
		goto out;

	err = -ENOBUFS;

	if (!f) {//创建fib_node
		new_f = kmem_cache_zalloc(fn_hash_kmem, GFP_KERNEL);
		if (new_f == NULL)
			goto out;

		INIT_HLIST_NODE(&new_f->fn_hash);
		INIT_LIST_HEAD(&new_f->fn_alias);
		new_f->fn_key = key;
		f = new_f;
	}

	new_fa = &f->fn_embedded_alias;
	if (new_fa->fa_info != NULL) {//new_fa->fa_info不为空，说明fn_embedded_alias已经被使用了，需要重新分配一个
		new_fa = kmem_cache_alloc(fn_alias_kmem, GFP_KERNEL);
		if (new_fa == NULL)
			goto out;
	}
	new_fa->fa_info = fi;
	new_fa->fa_tos = tos;
	new_fa->fa_type = cfg->fc_type;
	new_fa->fa_scope = cfg->fc_scope;
	new_fa->fa_state = 0;

	/*
	 * Insert new entry to the list.
	 */

	write_lock_bh(&fib_hash_lock);
	if (new_f)
		fib_insert_node(fz, new_f);//fib_node插入到fib_zone中
	//fa不为空，说明存在fib_node中存在fib_alias，只需要插入到fa->fa_list表头位置，也就说fa->list中是按照tos进行降序排列；fa为空，说明fib_node不存在fib_alias,只需要插入到fib_node中作为链表头	
	list_add_tail(&new_fa->fa_list,
		 (fa ? &fa->fa_list : &f->fn_alias));
	fib_hash_genid++;
	write_unlock_bh(&fib_hash_lock);

	if (new_f)
		fz->fz_nent++;
	rt_cache_flush(-1);//刷新缓存路由

	rtmsg_fib(RTM_NEWROUTE, key, new_fa, cfg->fc_dst_len, tb->tb_id,
		  &cfg->fc_nlinfo, 0);//发送RTM_NEWROUTE消息，通知用户空间
	return 0;

out:
	if (new_f)
		kmem_cache_free(fn_hash_kmem, new_f);
	fib_release_info(fi);
	return err;
}

/*
1. 通过掩码，找到对应的fib_zone
2. 通过目标前缀，找到对应的fib_node
3. 通过模糊匹配(tos和priority)，找到第一个满足要求的fib_alias。fib_node中的fib_alias按照tos的值进行降序排列
4. 继续遍历，不过需要精确匹配(因为极有可能会匹配上相同的tos): type、scope、protocol、下一跳是否一致。注意这里的精确匹配没有mss、mtu、rtt这样的值
5. 如果找到的fabric_alias满足条件，删除该fabric_alias
6. 如果fib_node中的fib_alias为空，删除fib_node
*/
static int fn_hash_delete(struct fib_table *tb, struct fib_config *cfg)
{
	struct fn_hash *table = (struct fn_hash*)tb->tb_data;
	struct fib_node *f;
	struct fib_alias *fa, *fa_to_delete;
	struct fn_zone *fz;
	__be32 key;

	if (cfg->fc_dst_len > 32)
		return -EINVAL;
	//根据掩码长度，找到对应的fib_zone。
	if ((fz  = table->fn_zones[cfg->fc_dst_len]) == NULL)
		return -ESRCH;//为空，返回NO such process错误

	key = 0;
	if (cfg->fc_dst) {
		if (cfg->fc_dst & ~FZ_MASK(fz))//dst地址中的host必须为0，否则返回 invalid argument错误
			return -EINVAL;
		key = fz_key(cfg->fc_dst, fz);//dst & 掩码
	}
	//找到fib_node。fib_node中保存的是目标前缀一样的路由项，可以tos和优先级、type、scope不一样的fib_alias
	f = fib_find_node(fz, key);

	if (!f)//没有找到
		fa = NULL;//fib_node没有找到，说明一定没有fib_alias
	else
		fa = fib_find_alias(&f->fn_alias, cfg->fc_tos, 0);//寻找第一个比cfg->fc_tos小的fib_alias
	if (!fa)
		return -ESRCH;

	fa_to_delete = NULL;
	fa = list_entry(fa->fa_list.prev, struct fib_alias, fa_list);
	list_for_each_entry_continue(fa, &f->fn_alias, fa_list) {
		struct fib_info *fi = fa->fa_info;

		if (fa->fa_tos != cfg->fc_tos)
			break;

		if ((!cfg->fc_type ||
		     fa->fa_type == cfg->fc_type) &&
		    (cfg->fc_scope == RT_SCOPE_NOWHERE ||
		     fa->fa_scope == cfg->fc_scope) &&
		    (!cfg->fc_protocol ||
		     fi->fib_protocol == cfg->fc_protocol) &&
		    fib_nh_match(cfg, fi) == 0) {//找到具体的路由项，这里的并没有包含mtu、mss、rtt等选项
			fa_to_delete = fa;
			break;
		}
	}
	//fa_to_delete不为空，表明找到了。
	if (fa_to_delete) {
		int kill_fn;

		fa = fa_to_delete;
		rtmsg_fib(RTM_DELROUTE, key, fa, cfg->fc_dst_len,
			  tb->tb_id, &cfg->fc_nlinfo, 0);//向netlink发送RTM_DELROUTE消息，通知用户空间

		kill_fn = 0;
		write_lock_bh(&fib_hash_lock);
		list_del(&fa->fa_list);//从fib_alias中删除
		if (list_empty(&f->fn_alias)) {//fib_node中的fn_alias为空，说明需要删除该fib_node
			hlist_del(&f->fn_hash);
			kill_fn = 1;
		}
		fib_hash_genid++;
		write_unlock_bh(&fib_hash_lock);

		if (fa->fa_state & FA_S_ACCESSED)
			rt_cache_flush(-1);//刷新缓存路由
		fn_free_alias(fa, f);
		if (kill_fn) {//fib_node为空，则删除
			fn_free_node(f);
			fz->fz_nent--;
		}

		return 0;
	}
	return -ESRCH;
}

static int fn_flush_list(struct fn_zone *fz, int idx)
{
	//获取hash表头，链表中保存的是fib_node
	struct hlist_head *head = &fz->fz_hash[idx];
	struct hlist_node *node, *n;
	struct fib_node *f;
	int found = 0;
	//遍历链表中的fib_node
	hlist_for_each_entry_safe(f, node, n, head, fn_hash) {
		struct fib_alias *fa, *fa_node;
		int kill_f;

		kill_f = 0;
		//遍历fib_node 中的fib_alias
		list_for_each_entry_safe(fa, fa_node, &f->fn_alias, fa_list) {
			struct fib_info *fi = fa->fa_info;

			if (fi && (fi->fib_flags&RTNH_F_DEAD)) {//如果路由项被标记为dead，删除该路由项
				write_lock_bh(&fib_hash_lock);
				list_del(&fa->fa_list);
				if (list_empty(&f->fn_alias)) {//fib_node中的fib_alias为空，说明需要删除该fib_node
					hlist_del(&f->fn_hash);
					kill_f = 1;
				}
				fib_hash_genid++;
				write_unlock_bh(&fib_hash_lock);

				fn_free_alias(fa, f);
				found++;
			}
		}
		if (kill_f) {
			fn_free_node(f);
			fz->fz_nent--;
		}
	}
	return found;
}
/*
删除路由项中标记为RTNH_F_DEAD的路由项
*/
static int fn_hash_flush(struct fib_table *tb)
{
	struct fn_hash *table = (struct fn_hash *) tb->tb_data;
	struct fn_zone *fz;
	int found = 0;
	//遍历每个fib_zone
	for (fz = table->fn_zone_list; fz; fz = fz->fz_next) {
		int i;
		//遍历每个装有fib_node的hash桶
		for (i = fz->fz_divisor - 1; i >= 0; i--)
			found += fn_flush_list(fz, i);
	}
	return found;
}


static inline int
fn_hash_dump_bucket(struct sk_buff *skb, struct netlink_callback *cb,
		     struct fib_table *tb,
		     struct fn_zone *fz,
		     struct hlist_head *head)
{
	struct hlist_node *node;
	struct fib_node *f;
	int i, s_i;

	s_i = cb->args[4];
	i = 0;
	hlist_for_each_entry(f, node, head, fn_hash) {
		struct fib_alias *fa;

		list_for_each_entry(fa, &f->fn_alias, fa_list) {
			if (i < s_i)
				goto next;

			if (fib_dump_info(skb, NETLINK_CB(cb->skb).pid,
					  cb->nlh->nlmsg_seq,
					  RTM_NEWROUTE,
					  tb->tb_id,
					  fa->fa_type,
					  fa->fa_scope,
					  f->fn_key,
					  fz->fz_order,
					  fa->fa_tos,
					  fa->fa_info,
					  NLM_F_MULTI) < 0) {
				cb->args[4] = i;
				return -1;
			}
		next:
			i++;
		}
	}
	cb->args[4] = i;
	return skb->len;
}

static inline int
fn_hash_dump_zone(struct sk_buff *skb, struct netlink_callback *cb,
		   struct fib_table *tb,
		   struct fn_zone *fz)
{
	int h, s_h;

	if (fz->fz_hash == NULL)
		return skb->len;
	s_h = cb->args[3];
	for (h = s_h; h < fz->fz_divisor; h++) {
		if (hlist_empty(&fz->fz_hash[h]))
			continue;
		if (fn_hash_dump_bucket(skb, cb, tb, fz, &fz->fz_hash[h]) < 0) {
			cb->args[3] = h;
			return -1;
		}
		memset(&cb->args[4], 0,
		       sizeof(cb->args) - 4*sizeof(cb->args[0]));
	}
	cb->args[3] = h;
	return skb->len;
}

static int fn_hash_dump(struct fib_table *tb, struct sk_buff *skb, struct netlink_callback *cb)
{
	int m, s_m;
	struct fn_zone *fz;
	struct fn_hash *table = (struct fn_hash*)tb->tb_data;

	s_m = cb->args[2];
	read_lock(&fib_hash_lock);
	for (fz = table->fn_zone_list, m=0; fz; fz = fz->fz_next, m++) {
		if (m < s_m) continue;
		if (fn_hash_dump_zone(skb, cb, tb, fz) < 0) {
			cb->args[2] = m;
			read_unlock(&fib_hash_lock);
			return -1;
		}
		memset(&cb->args[3], 0,
		       sizeof(cb->args) - 3*sizeof(cb->args[0]));
	}
	read_unlock(&fib_hash_lock);
	cb->args[2] = m;
	return skb->len;
}

void __init fib_hash_init(void)
{
	fn_hash_kmem = kmem_cache_create("ip_fib_hash", sizeof(struct fib_node),
					 0, SLAB_PANIC, NULL);

	fn_alias_kmem = kmem_cache_create("ip_fib_alias", sizeof(struct fib_alias),
					  0, SLAB_PANIC, NULL);

}
//创建路由表并初始化部分字段
struct fib_table *fib_hash_table(u32 id)
{
	struct fib_table *tb;
	//分配fib_table和fn_hash一起分配
	tb = kmalloc(sizeof(struct fib_table) + sizeof(struct fn_hash),
		     GFP_KERNEL);
	if (tb == NULL)
		return NULL;
	//初始化fib_table
	tb->tb_id = id;
	tb->tb_default = -1;
	tb->tb_lookup = fn_hash_lookup;//查询路由项
	tb->tb_insert = fn_hash_insert;//插入路由项
	tb->tb_delete = fn_hash_delete;//删除路由项
	tb->tb_flush = fn_hash_flush;//清空路由项
	tb->tb_select_default = fn_hash_select_default;//默认路由项
	tb->tb_dump = fn_hash_dump;
	memset(tb->tb_data, 0, sizeof(struct fn_hash));
	return tb;
}

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

struct fib_iter_state {
	struct seq_net_private p;
	struct fn_zone	*zone;
	int		bucket;
	struct hlist_head *hash_head;
	struct fib_node *fn;
	struct fib_alias *fa;
	loff_t pos;
	unsigned int genid;
	int valid;
};

static struct fib_alias *fib_get_first(struct seq_file *seq)
{
	struct fib_iter_state *iter = seq->private;
	struct fib_table *main_table;
	struct fn_hash *table;

	main_table = fib_get_table(seq_file_net(seq), RT_TABLE_MAIN);
	table = (struct fn_hash *)main_table->tb_data;

	iter->bucket    = 0;
	iter->hash_head = NULL;
	iter->fn        = NULL;
	iter->fa        = NULL;
	iter->pos	= 0;
	iter->genid	= fib_hash_genid;
	iter->valid	= 1;

	for (iter->zone = table->fn_zone_list; iter->zone;
	     iter->zone = iter->zone->fz_next) {
		int maxslot;

		if (!iter->zone->fz_nent)
			continue;

		iter->hash_head = iter->zone->fz_hash;
		maxslot = iter->zone->fz_divisor;

		for (iter->bucket = 0; iter->bucket < maxslot;
		     ++iter->bucket, ++iter->hash_head) {
			struct hlist_node *node;
			struct fib_node *fn;

			hlist_for_each_entry(fn,node,iter->hash_head,fn_hash) {
				struct fib_alias *fa;

				list_for_each_entry(fa,&fn->fn_alias,fa_list) {
					iter->fn = fn;
					iter->fa = fa;
					goto out;
				}
			}
		}
	}
out:
	return iter->fa;
}

static struct fib_alias *fib_get_next(struct seq_file *seq)
{
	struct fib_iter_state *iter = seq->private;
	struct fib_node *fn;
	struct fib_alias *fa;

	/* Advance FA, if any. */
	fn = iter->fn;
	fa = iter->fa;
	if (fa) {
		BUG_ON(!fn);
		list_for_each_entry_continue(fa, &fn->fn_alias, fa_list) {
			iter->fa = fa;
			goto out;
		}
	}

	fa = iter->fa = NULL;

	/* Advance FN. */
	if (fn) {
		struct hlist_node *node = &fn->fn_hash;
		hlist_for_each_entry_continue(fn, node, fn_hash) {
			iter->fn = fn;

			list_for_each_entry(fa, &fn->fn_alias, fa_list) {
				iter->fa = fa;
				goto out;
			}
		}
	}

	fn = iter->fn = NULL;

	/* Advance hash chain. */
	if (!iter->zone)
		goto out;

	for (;;) {
		struct hlist_node *node;
		int maxslot;

		maxslot = iter->zone->fz_divisor;

		while (++iter->bucket < maxslot) {
			iter->hash_head++;

			hlist_for_each_entry(fn, node, iter->hash_head, fn_hash) {
				list_for_each_entry(fa, &fn->fn_alias, fa_list) {
					iter->fn = fn;
					iter->fa = fa;
					goto out;
				}
			}
		}

		iter->zone = iter->zone->fz_next;

		if (!iter->zone)
			goto out;

		iter->bucket = 0;
		iter->hash_head = iter->zone->fz_hash;

		hlist_for_each_entry(fn, node, iter->hash_head, fn_hash) {
			list_for_each_entry(fa, &fn->fn_alias, fa_list) {
				iter->fn = fn;
				iter->fa = fa;
				goto out;
			}
		}
	}
out:
	iter->pos++;
	return fa;
}

static struct fib_alias *fib_get_idx(struct seq_file *seq, loff_t pos)
{
	struct fib_iter_state *iter = seq->private;
	struct fib_alias *fa;

	if (iter->valid && pos >= iter->pos && iter->genid == fib_hash_genid) {
		fa   = iter->fa;
		pos -= iter->pos;
	} else
		fa = fib_get_first(seq);

	if (fa)
		while (pos && (fa = fib_get_next(seq)))
			--pos;
	return pos ? NULL : fa;
}

static void *fib_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(fib_hash_lock)
{
	void *v = NULL;

	read_lock(&fib_hash_lock);
	if (fib_get_table(seq_file_net(seq), RT_TABLE_MAIN))
		v = *pos ? fib_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
	return v;
}

static void *fib_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return v == SEQ_START_TOKEN ? fib_get_first(seq) : fib_get_next(seq);
}

static void fib_seq_stop(struct seq_file *seq, void *v)
	__releases(fib_hash_lock)
{
	read_unlock(&fib_hash_lock);
}

static unsigned fib_flag_trans(int type, __be32 mask, struct fib_info *fi)
{
	static const unsigned type2flags[RTN_MAX + 1] = {
		[7] = RTF_REJECT, [8] = RTF_REJECT,
	};
	unsigned flags = type2flags[type];

	if (fi && fi->fib_nh->nh_gw)
		flags |= RTF_GATEWAY;
	if (mask == htonl(0xFFFFFFFF))
		flags |= RTF_HOST;
	flags |= RTF_UP;
	return flags;
}

/*
 *	This outputs /proc/net/route.
 *
 *	It always works in backward compatibility mode.
 *	The format of the file is not supposed to be changed.
 */
static int fib_seq_show(struct seq_file *seq, void *v)
{
	struct fib_iter_state *iter;
	int len;
	__be32 prefix, mask;
	unsigned flags;
	struct fib_node *f;
	struct fib_alias *fa;
	struct fib_info *fi;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-127s\n", "Iface\tDestination\tGateway "
			   "\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU"
			   "\tWindow\tIRTT");
		goto out;
	}

	iter	= seq->private;
	f	= iter->fn;
	fa	= iter->fa;
	fi	= fa->fa_info;
	prefix	= f->fn_key;
	mask	= FZ_MASK(iter->zone);
	flags	= fib_flag_trans(fa->fa_type, mask, fi);
	if (fi)
		seq_printf(seq,
			 "%s\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u%n",
			 fi->fib_dev ? fi->fib_dev->name : "*", prefix,
			 fi->fib_nh->nh_gw, flags, 0, 0, fi->fib_priority,
			 mask, (fi->fib_advmss ? fi->fib_advmss + 40 : 0),
			 fi->fib_window,
			 fi->fib_rtt >> 3, &len);
	else
		seq_printf(seq,
			 "*\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u%n",
			 prefix, 0, flags, 0, 0, 0, mask, 0, 0, 0, &len);

	seq_printf(seq, "%*s\n", 127 - len, "");
out:
	return 0;
}

static const struct seq_operations fib_seq_ops = {
	.start  = fib_seq_start,
	.next   = fib_seq_next,
	.stop   = fib_seq_stop,
	.show   = fib_seq_show,
};

static int fib_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &fib_seq_ops,
			    sizeof(struct fib_iter_state));
}

static const struct file_operations fib_seq_fops = {
	.owner		= THIS_MODULE,
	.open           = fib_seq_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release	= seq_release_net,
};

int __net_init fib_proc_init(struct net *net)
{
	if (!proc_net_fops_create(net, "route", S_IRUGO, &fib_seq_fops))
		return -ENOMEM;
	return 0;
}

void __net_exit fib_proc_exit(struct net *net)
{
	proc_net_remove(net, "route");
}
#endif /* CONFIG_PROC_FS */
