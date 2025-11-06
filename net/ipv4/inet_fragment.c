/*
 * inet fragments management
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * 		Authors:	Pavel Emelyanov <xemul@openvz.org>
 *				Started as consolidation of ipv4/ip_fragment.c,
 *				ipv6/reassembly. and ipv6 nf conntrack reassembly
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>

#include <net/inet_frag.h>

static void inet_frag_secret_rebuild(unsigned long dummy)
{
	struct inet_frags *f = (struct inet_frags *)dummy;
	unsigned long now = jiffies;
	int i;

	write_lock(&f->lock);
	get_random_bytes(&f->rnd, sizeof(u32));
	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_queue *q;
		struct hlist_node *p, *n;

		hlist_for_each_entry_safe(q, p, n, &f->hash[i], list) {
			unsigned int hval = f->hashfn(q);

			if (hval != i) {
				hlist_del(&q->list);

				/* Relink to new hash chain. */
				hlist_add_head(&q->list, &f->hash[hval]);
			}
		}
	}
	write_unlock(&f->lock);

	mod_timer(&f->secret_timer, now + f->secret_interval);
}

void inet_frags_init(struct inet_frags *f)
{
	int i;

	for (i = 0; i < INETFRAGS_HASHSZ; i++)
		INIT_HLIST_HEAD(&f->hash[i]);//初始化 hash队列头

	rwlock_init(&f->lock);

	f->rnd = (u32) ((num_physpages ^ (num_physpages>>7)) ^
				   (jiffies ^ (jiffies >> 6)));//计算随机数

	setup_timer(&f->secret_timer, inet_frag_secret_rebuild,
			(unsigned long)f);//设置定时器函数,定时间隔调整哈希队列
	f->secret_timer.expires = jiffies + f->secret_interval;//设置过期时间
	add_timer(&f->secret_timer);//启用定时器
}
EXPORT_SYMBOL(inet_frags_init);

void inet_frags_init_net(struct netns_frags *nf)
{
	nf->nqueues = 0;
	atomic_set(&nf->mem, 0);
	INIT_LIST_HEAD(&nf->lru_list);
}
EXPORT_SYMBOL(inet_frags_init_net);

void inet_frags_fini(struct inet_frags *f)
{
	del_timer(&f->secret_timer);
}
EXPORT_SYMBOL(inet_frags_fini);

void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f)
{
	nf->low_thresh = 0;

	local_bh_disable();
	inet_frag_evictor(nf, f);
	local_bh_enable();
}
EXPORT_SYMBOL(inet_frags_exit_net);

static inline void fq_unlink(struct inet_frag_queue *fq, struct inet_frags *f)
{
	write_lock(&f->lock);
	hlist_del(&fq->list);//从INET分段管理结构的哈希队列摘链
	list_del(&fq->lru_list);//从老化队列脱链,网络空间分段管理结构的老化队列
	fq->net->nqueues--;//递减网络空间分段管理结构的队列计数
	write_unlock(&f->lock);
}

void inet_frag_kill(struct inet_frag_queue *fq, struct inet_frags *f)
{
	if (del_timer(&fq->timer))//摘除队列定时器
		atomic_dec(&fq->refcnt);//递减使用计数

	if (!(fq->last_in & INET_FRAG_COMPLETE)) {//如果队列没有设置完成标志
		fq_unlink(fq, f);//将队列头摘链
		atomic_dec(&fq->refcnt);//递减使用计数
		fq->last_in |= INET_FRAG_COMPLETE;//设置完成标志
	}
}

EXPORT_SYMBOL(inet_frag_kill);

static inline void frag_kfree_skb(struct netns_frags *nf, struct inet_frags *f,
		struct sk_buff *skb, int *work)
{
	if (work)
		*work -= skb->truesize;//递减释放长度

	atomic_sub(skb->truesize, &nf->mem);//递减数据包占用内存数
	if (f->skb_free)//如果分段队列指定了释放函数,就调用它
		f->skb_free(skb);
	kfree_skb(skb);//释放数据包
}

void inet_frag_destroy(struct inet_frag_queue *q, struct inet_frags *f,
					int *work)
{
	struct sk_buff *fp;
	struct netns_frags *nf;

	BUG_TRAP(q->last_in & INET_FRAG_COMPLETE);//检查完成标志
	BUG_TRAP(del_timer(&q->timer) == 0);//摘除队列定时器

	/* Release all fragment data. */
	fp = q->fragments;//取得第一个分段数据包
	nf = q->net;//取得网络空间的分段管理结构
	while (fp) {//循环释放分段数据包
		struct sk_buff *xp = fp->next;

		frag_kfree_skb(nf, f, fp, work);//调用释放数据包函数
		fp = xp;
	}

	if (work)
		*work -= f->qsize;//计算未清除长度
	atomic_sub(f->qsize, &nf->mem);//递减数据包占用内存数

	if (f->destructor)//如果INET分段管理结构指定了销毁函数
		f->destructor(q);//调用销毁函数
	kfree(q);//释放 INET分段队列头

}
EXPORT_SYMBOL(inet_frag_destroy);

int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f)
{
	struct inet_frag_queue *q;//INET的分段队列头指针
	int work, evicted = 0;

	work = atomic_read(&nf->mem) - nf->low_thresh;//计算要清除的长度
	while (work > 0) {
		read_lock(&f->lock);
		if (list_empty(&nf->lru_list)) {//如果老化队列已经空就退出
			read_unlock(&f->lock);
			break;
		}
		//从老化队列前面取队列头,正在操作的队列在ip_frag_gueue()函数中总是移动到老化队列尾部，因此不会受到影响
		q = list_first_entry(&nf->lru_list,
				struct inet_frag_queue, lru_list);//从老化队列中取得分段队列头指针
		atomic_inc(&q->refcnt);
		read_unlock(&f->lock);

		spin_lock(&q->lock);
		if (!(q->last_in & INET_FRAG_COMPLETE))//还没有设置队列完成标志
			inet_frag_kill(q, f);//将INET分段队列头摘链
		spin_unlock(&q->lock);

		if (atomic_dec_and_test(&q->refcnt))//递减使用计数并测试计数是否为0
			inet_frag_destroy(q, f, &work);//释放分段数据包和分段队列头，调整清除长度
		evicted++;//递增清除计数
	}

	return evicted;//返回清除计数
}
EXPORT_SYMBOL(inet_frag_evictor);

static struct inet_frag_queue *inet_frag_intern(struct netns_frags *nf,
		struct inet_frag_queue *qp_in, struct inet_frags *f,
		void *arg)
{
	struct inet_frag_queue *qp;//INET分段队列头指针
#ifdef CONFIG_SMP
	struct hlist_node *n;
#endif
	unsigned int hash;

	write_lock(&f->lock);
	/*
	 * While we stayed w/o the lock other CPU could update
	 * the rnd seed, so we need to re-calculate the hash
	 * chain. Fortunatelly the qp_in can be used to get one.
	 */
	hash = f->hashfn(qp_in);//计算hash值
#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could be created on other cpu, while we
	 * promoted read lock to write lock.
	 */
	hlist_for_each_entry(qp, n, &f->hash[hash], list) {
		if (qp->net == nf && f->match(qp, arg)) {
			atomic_inc(&qp->refcnt);
			write_unlock(&f->lock);
			qp_in->last_in |= INET_FRAG_COMPLETE;
			inet_frag_put(qp_in, f);
			return qp;
		}
	}
#endif
	qp = qp_in;//指向新建的分段队列头
	if (!mod_timer(&qp->timer, jiffies + nf->timeout))//修改定时器的超时时间
		atomic_inc(&qp->refcnt);//递增使用计数

	atomic_inc(&qp->refcnt);//递增使用计数
	hlist_add_head(&qp->list, &f->hash[hash]);//链人INET分段管理结构的哈希队列
	list_add_tail(&qp->lru_list, &nf->lru_list);//链人网络空间的分段老化队列
	nf->nqueues++;//递增队列计数
	write_unlock(&f->lock);
	return qp;//返回新建的INET分段队列头指针
}

static struct inet_frag_queue *inet_frag_alloc(struct netns_frags *nf,
		struct inet_frags *f, void *arg)
{
	struct inet_frag_queue *q;//INET分段队列头指针

	q = kzalloc(f->qsize, GFP_ATOMIC);//按IP分段队列结构的长度分配空间
	if (q == NULL)
		return NULL;

	f->constructor(q, arg);//调用构造函数，初始化分段队列头。ip4_frag_init()
	atomic_add(f->qsize, &nf->mem);//累计网络空间的分段内存计数器
	setup_timer(&q->timer, f->frag_expire, (unsigned long)q);//安装定时器
	spin_lock_init(&q->lock);
	atomic_set(&q->refcnt, 1);//初始化使用计数
	q->net = nf;//记录网络空间的分段管理结构指针

	return q;//返回创建的分段队列头指针
}

static struct inet_frag_queue *inet_frag_create(struct netns_frags *nf,
		struct inet_frags *f, void *arg)
{
	struct inet_frag_queue *q;//INET分段队列头指针

	q = inet_frag_alloc(nf, f, arg);//分配队列头结构空间
	if (q == NULL)
		return NULL;

	return inet_frag_intern(nf, q, f, arg);
}

struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash)
{
	struct inet_frag_queue *q;//INET 分段队列头
	struct hlist_node *n;//hash节点

	hlist_for_each_entry(q, n, &f->hash[hash], list) {//依次从哈希队列获取每个队列头
		if (q->net == nf && f->match(q, key)) {//如果同属一个网络空间分段管理结构并且调用匹配函数对比成功。 ip4_frag_match()
			atomic_inc(&q->refcnt);//递增队列头使用计数
			read_unlock(&f->lock);
			return q;//返回找到的分段队列头
		}
	}
	read_unlock(&f->lock);

	return inet_frag_create(nf, f, key);//创建INET分段队列头
}
EXPORT_SYMBOL(inet_frag_find);
