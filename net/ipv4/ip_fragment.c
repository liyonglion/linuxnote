/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP fragmentation functionality.
 *
 * Version:	$Id: ip_fragment.c,v 1.59 2002/01/12 07:54:56 davem Exp $
 *
 * Authors:	Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 *		Alan Cox <Alan.Cox@linux.org>
 *
 * Fixes:
 *		Alan Cox	:	Split from ip.c , see ip_input.c for history.
 *		David S. Miller :	Begin massive cleanup...
 *		Andi Kleen	:	Add sysctls.
 *		xxxx		:	Overlapfrag bug.
 *		Ultima          :       ip_expire() kernel panic.
 *		Bill Hawes	:	Frag accounting and evictor fixes.
 *		John McDonald	:	0 length frag bug.
 *		Alexey Kuznetsov:	SMP races, threading, cleanup.
 *		Patrick McHardy :	LRU queue of frag heads for evictor.
 */

#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/inet_frag.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>

/* NOTE. Logic of IP defragmentation is parallel to corresponding IPv6
 * code now. If you change something here, _PLEASE_ update ipv6/reassembly.c
 * as well. Or notify me, at least. --ANK
 */

static int sysctl_ipfrag_max_dist __read_mostly = 64;

struct ipfrag_skb_cb
{
	struct inet_skb_parm	h;
	int			offset;
};

#define FRAG_CB(skb)	((struct ipfrag_skb_cb*)((skb)->cb))

/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq {
	struct inet_frag_queue q;

	u32		user;
	__be32		saddr;
	__be32		daddr;
	__be16		id;
	u8		protocol;
	int             iif;
	unsigned int    rid;
	struct inet_peer *peer;
};

static struct inet_frags ip4_frags;

int ip_frag_nqueues(struct net *net)
{
	return net->ipv4.frags.nqueues;
}

int ip_frag_mem(struct net *net)
{
	return atomic_read(&net->ipv4.frags.mem);
}

static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,
			 struct net_device *dev);

struct ip4_create_arg {
	struct iphdr *iph;
	u32 user;
};

static unsigned int ipqhashfn(__be16 id, __be32 saddr, __be32 daddr, u8 prot)
{
	return jhash_3words((__force u32)id << 16 | prot,
			    (__force u32)saddr, (__force u32)daddr,
			    ip4_frags.rnd) & (INETFRAGS_HASHSZ - 1);
}

static unsigned int ip4_hashfn(struct inet_frag_queue *q)
{
	struct ipq *ipq;

	ipq = container_of(q, struct ipq, q);
	return ipqhashfn(ipq->id, ipq->saddr, ipq->daddr, ipq->protocol);
}

static int ip4_frag_match(struct inet_frag_queue *q, void *a)
{
	struct ipq *qp;
	struct ip4_create_arg *arg = a;

	qp = container_of(q, struct ipq, q);
	return (qp->id == arg->iph->id &&
			qp->saddr == arg->iph->saddr &&
			qp->daddr == arg->iph->daddr &&
			qp->protocol == arg->iph->protocol &&
			qp->user == arg->user);
}

/* Memory Tracking Functions. */
static __inline__ void frag_kfree_skb(struct netns_frags *nf,
		struct sk_buff *skb, int *work)
{
	if (work)
		*work -= skb->truesize;
	atomic_sub(skb->truesize, &nf->mem);
	kfree_skb(skb);
}

static void ip4_frag_init(struct inet_frag_queue *q, void *a)
{
	struct ipq *qp = container_of(q, struct ipq, q);
	struct ip4_create_arg *arg = a;

	qp->protocol = arg->iph->protocol;
	qp->id = arg->iph->id;
	qp->saddr = arg->iph->saddr;
	qp->daddr = arg->iph->daddr;
	qp->user = arg->user;
	qp->peer = sysctl_ipfrag_max_dist ?
		inet_getpeer(arg->iph->saddr, 1) : NULL;
}

static __inline__ void ip4_frag_free(struct inet_frag_queue *q)
{
	struct ipq *qp;

	qp = container_of(q, struct ipq, q);
	if (qp->peer)
		inet_putpeer(qp->peer);
}


/* Destruction primitives. */

static __inline__ void ipq_put(struct ipq *ipq)
{
	inet_frag_put(&ipq->q, &ip4_frags);
}

/* Kill ipq entry. It is not destroyed immediately,
 * because caller (and someone more) holds reference count.
 */
static void ipq_kill(struct ipq *ipq)
{
	inet_frag_kill(&ipq->q, &ip4_frags);
}

/* Memory limiting on fragments.  Evictor trashes the oldest
 * fragment queue until we are back under the threshold.
 */
static void ip_evictor(struct net *net)
{
	int evicted;

	evicted = inet_frag_evictor(&net->ipv4.frags, &ip4_frags);
	if (evicted)
		IP_ADD_STATS_BH(IPSTATS_MIB_REASMFAILS, evicted);
}

/*
 * Oops, a fragment queue timed out.  Kill it and send an ICMP reply.
 */
static void ip_expire(unsigned long arg)
{
	struct ipq *qp;

	qp = container_of((struct inet_frag_queue *) arg, struct ipq, q);

	spin_lock(&qp->q.lock);

	if (qp->q.last_in & INET_FRAG_COMPLETE)
		goto out;

	ipq_kill(qp);

	IP_INC_STATS_BH(IPSTATS_MIB_REASMTIMEOUT);
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);

	if ((qp->q.last_in & INET_FRAG_FIRST_IN) && qp->q.fragments != NULL) {
		struct sk_buff *head = qp->q.fragments;
		struct net *net;

		net = container_of(qp->q.net, struct net, ipv4.frags);
		/* Send an ICMP "Fragment Reassembly Timeout" message. */
		if ((head->dev = dev_get_by_index(net, qp->iif)) != NULL) {
			icmp_send(head, ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME, 0);
			dev_put(head->dev);
		}
	}
out:
	spin_unlock(&qp->q.lock);
	ipq_put(qp);
}

/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 */
static inline struct ipq *ip_find(struct net *net, struct iphdr *iph, u32 user)
{
	struct inet_frag_queue *q;
	struct ip4_create_arg arg;
	unsigned int hash;

	arg.iph = iph;
	arg.user = user;

	read_lock(&ip4_frags.lock);
	hash = ipqhashfn(iph->id, iph->saddr, iph->daddr, iph->protocol);

	q = inet_frag_find(&net->ipv4.frags, &ip4_frags, &arg, hash);
	if (q == NULL)
		goto out_nomem;

	return container_of(q, struct ipq, q);

out_nomem:
	LIMIT_NETDEBUG(KERN_ERR "ip_frag_create: no memory left !\n");
	return NULL;
}

/* Is the fragment too far ahead to be part of ipq? */
static inline int ip_frag_too_far(struct ipq *qp)
{
	struct inet_peer *peer = qp->peer;
	unsigned int max = sysctl_ipfrag_max_dist;
	unsigned int start, end;

	int rc;

	if (!peer || !max)
		return 0;

	start = qp->rid;
	end = atomic_inc_return(&peer->rid);
	qp->rid = end;

	rc = qp->q.fragments && (end - start) > max;

	if (rc) {
		IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);
	}

	return rc;
}

static int ip_frag_reinit(struct ipq *qp)
{
	struct sk_buff *fp;

	if (!mod_timer(&qp->q.timer, jiffies + qp->q.net->timeout)) {
		atomic_inc(&qp->q.refcnt);
		return -ETIMEDOUT;
	}

	fp = qp->q.fragments;
	do {
		struct sk_buff *xp = fp->next;
		frag_kfree_skb(qp->q.net, fp, NULL);
		fp = xp;
	} while (fp);

	qp->q.last_in = 0;
	qp->q.len = 0;
	qp->q.meat = 0;
	qp->q.fragments = NULL;
	qp->iif = 0;

	return 0;
}

/* Add new segment to existing queue. */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct sk_buff *prev, *next;
	struct net_device *dev;
	int flags, offset;
	int ihl, end;
	int err = -ENOENT;

	if (qp->q.last_in & INET_FRAG_COMPLETE)//如果分段队列已经接收完成就返回
		goto err;

	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&//如果数据包没有分段标志
	    unlikely(ip_frag_too_far(qp)) &&//检查分段队列是否间隔过大
	    unlikely(err = ip_frag_reinit(qp))) {//重新调整分段队列是否出错
		ipq_kill(qp);//清除分段队列返回
		goto err;
	}

	offset = ntohs(ip_hdr(skb)->frag_off);//取得分段数据块的偏移位置
	flags = offset & ~IP_OFFSET;//取得分段标志
	offset &= IP_OFFSET;//对齐边界
	offset <<= 3;		/* offset is in 8-byte chunks 按8字节边界对齐*/
	ihl = ip_hdrlen(skb);//获取分段数据块的 IP头部长度

	/* Determine the position of this fragment. */
	end = offset + skb->len - ihl;//确定分段数据块的结束地址
	err = -EINVAL;

	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {//如果是最后一个分段数据块
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrrupted.
		 */
		if (end < qp->q.len ||//如果结束位置小于前一个的结束位置，则出错返回
		    ((qp->q.last_in & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto err;
		qp->q.last_in |= INET_FRAG_LAST_IN;//设置最后一个数据包标志
		qp->q.len = end;//记录数据块的结束地址
	} else {
		if (end&7) {//如果分段数据块结束地址没有按8字节对齐
			end &= ~7;//按8字节对齐
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)//检查检验和标志
				skb->ip_summed = CHECKSUM_NONE;//设置无效检验和标志
		}
		if (end > qp->q.len) {//结束地址大于前一个的分段数据块的结束地址
			/* Some bits beyond end -> corruption. */
			if (qp->q.last_in & INET_FRAG_LAST_IN)//如果队列设置了最后分段数据包标志,表示前一个是最后一个数据包，出错返回
				goto err;
			qp->q.len = end;//记录当前分段数据块的结束位置
		}
	}
	if (end == offset)//如果分段数据块结束位置等于起始位置，出错返回
		goto err;

	err = -ENOMEM;
	if (pskb_pull(skb, ihl) == NULL)//检查数据块IP头部长度,调整数据块起始地址跳过IP头部,调整数据块的总长度
		goto err;

	err = pskb_trim_rcsum(skb, end - offset);//检查数据块的总长度,调整为正确的长度值
	if (err)
		goto err;

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment, right?
	 */
	//开始确定插人位置,prev是插人位置的前一个数据包,next是插入位置的后一个数据包
	prev = NULL;//用于记录插人位置前面的分段数据包
	//依次检查分段队列的每一个数据包,确定插人位置
	for (next = qp->q.fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)//对比当前分段数据块的偏移位置
			break;	/* bingo! 如果大于就找到了它后面的分段数据包*/
		prev = next;//否则就是它前面的分段数据包
	}

	/* We found where to put this one.  Check for overlap with
	 * preceding fragment, and, if needed, align things so that
	 * any overlaps are eliminated.
	 */
	if (prev) {//如果找到了前面的分段数据包，就要检查是否与当前数据包重叠
		int i = (FRAG_CB(prev)->offset + prev->len) - offset;//计算重叠字节数

		if (i > 0) {//如果重叠
			offset += i;//调整当前分段数据块偏移值，跳过重叠部分
			err = -EINVAL;
			if (end <= offset)//如果分段数据块结束位置小于开始位置，出错返回
				goto err;
			err = -ENOMEM;
			if (!pskb_pull(skb, i))//调整当前分段数据块起始地址和长度，消除重叠
				goto err;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;//设置无效检验和标志
		}
	}

	err = -ENOMEM;
	//如果找到了后边的分段数据包,并且重叠也要调整消除重叠
	while (next && FRAG_CB(next)->offset < end) {
		int i = end - FRAG_CB(next)->offset; /* overlap is 'i' bytes 计算重叠字节数 */

		if (i < next->len) {//没有全部重叠
			/* Eat head of the next overlapped fragment
			 * and leave the loop. The next ones cannot overlap.
			 */
			if (!pskb_pull(next, i))//调整后面数据块的起始地址和长度,调整消除重叠
				goto err;
			FRAG_CB(next)->offset += i;//调整后面数据块的偏移位置
			qp->q.meat -= i;//记录差距值
			if (next->ip_summed != CHECKSUM_UNNECESSARY)
				next->ip_summed = CHECKSUM_NONE;//设置无效检验和标志
			break;
		} else {//全部重叠就释放后面的分段数据包
			struct sk_buff *free_it = next;//记录要释放的分段数据包

			/* Old fragment is completely overridden with
			 * new one drop it.
			 */
			next = next->next;//指向下一个分段数据包

			if (prev)//如果前面的分段数据包存在
				prev->next = next;//使它与下一个分段数据包挂钩,与释放的数据包脱离关系
			else
				qp->q.fragments = next;//前面没有数据包就将下一个数据包靠前

			qp->q.meat -= free_it->len;//记录差距值
			frag_kfree_skb(qp->q.net, free_it, NULL);//释放数据包
		}
	}

	FRAG_CB(skb)->offset = offset;//记录数据块的偏移位置

	/* Insert this fragment in the chain of fragments. */
	skb->next = next;//指向插人位置后面的数据包
	if (prev)//如果插人位置前面有数据包
		prev->next = skb;//与前面的数据包挂钩
	else
		qp->q.fragments = skb;//前面没有分段数据包就放在队列前面

	dev = skb->dev;//取得数据包的网络设备结构
	if (dev) {
		qp->iif = dev->ifindex;//分段队列记录网络设备的ID
		skb->dev = NULL;//清空数据包的设备指针
	}
	qp->q.stamp = skb->tstamp;//记录时间戳
	qp->q.meat += skb->len;//缩小差距值
	atomic_add(skb->truesize, &qp->q.net->mem);//累计分段数据包的总内存数
	if (offset == 0)//如果是第一个分段数据块
		qp->q.last_in |= INET_FRAG_FIRST_IN;//设置接收了第一个分段数据包标志

	if (qp->q.last_in == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    qp->q.meat == qp->q.len)//如果接收了全部的分段数据包
		return ip_frag_reasm(qp, prev, dev);//重组数据包

	write_lock(&ip4_frags.lock);
	list_move_tail(&qp->q.lru_list, &qp->q.net->lru_list);//将分段队列结构链人老化队列的尾部
	write_unlock(&ip4_frags.lock);
	return -EINPROGRESS;

err:
	kfree_skb(skb);//释放数据包
	return err;
}


/* Build a new IP datagram from all its fragments. */

static int ip_frag_reasm(struct ipq *qp, struct sk_buff *prev,
			 struct net_device *dev)
{
	struct iphdr *iph;
	struct sk_buff *fp, *head = qp->q.fragments;//指向分段队列的第一个数据包
	int len;
	int ihlen;
	int err;

	ipq_kill(qp);//将分段队列结构从它所在的队列中脱链,摘除定时器

	/* Make the one we just received the head. */
	/*检查是否还有足够的内存可用,并确保第一个数据包的正确性*/
	if (prev) {//参数prev指向前面的数据包(处于当前接收数据包前面)
		head = prev->next;//指向当前接收的数据包(乱序到达,可能不是最后一个)
		fp = skb_clone(head, GFP_ATOMIC);//克隆(复制)当前接收的数据包
		if (!fp)//复制失败退出
			goto out_nomem;

		fp->next = head->next;//记录原来的队列关系，与后面的数据包挂钩
		prev->next = fp;//与前面的数据包挂钩

		skb_morph(head, qp->q.fragments);//将 head 变异为队列的第一个数据包,就是将当前接收的数据包结构作为第一个数据包,清空原来内容、复制第一个数据包的内容
		head->next = qp->q.fragments->next;//指向队列中的第二个数据包
		//将 head 设置为队列第一个数据包结构
		kfree_skb(qp->q.fragments);//释放原来的第一个数据包结构
		qp->q.fragments = head;//head 成为第一个数据包
	}

	BUG_TRAP(head != NULL);//检查第一个数据包是否为空
	BUG_TRAP(FRAG_CB(head)->offset == 0);//检查第一个数据块偏移是否正确

	/* Allocate a new buffer for the datagram. */
	ihlen = ip_hdrlen(head);//获取第一个数据包的 IP头部长度
	len = ihlen + qp->q.len;//计算主数据块的长度

	err = -E2BIG;
	if (len > 65535)//如果主数据块长度超过最大极限64K,返回
		goto out_oversize;

	/* Head of list must not be cloned. */
	/*函数中的if语句很容易误解,可能会对它的必要性产生怀疑,其实这段语句有两方面的作用:验证内存空间和获取正确的第一个数据包。
	因为重组过程需要申请新的数据包空间,提前验证内存空间可避免后面的多余操作,第一个数据包将用作主数据包,它的正确性是重组的关键。*/
	if (skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
		goto out_nomem;//如果第一个数据包是克隆的数据包,就要重新分配缓冲块和共享结构空间然后复制数据块和共享结构内容,记录下缓冲块、数据块的起始和结束地址

	/* If the first fragment is fragmented itself, we split
	 * it to two chunks: the first with data and paged part
	 * and the second, holding only fragments. */
	/*
	这里要考虑第一个数据包是否带有分段数据包,如果它带有分段数据包,则先转移到IP分段队列中来;转移操作并不能直接通过数据包的指针链人、链出实现,
	而是需要建立一个转移数据包。因此代码中先分配一个转移数据包,使它接手第一个数据包的分段队列,成为分段队列的新主人。这个转移数据包自身并不带有基本数据块,
	因此不需要申请缓冲块,只是分配了数据包空间和共享数据结构空间,这个分配过程肯定可以成功,这是前面克降验证的原因。转移数据包只需要接手第一个数据包的分段数据包队列,
	因此它的数据块总长度等于分段数据块的总长度。第一个数据包因为交出了分段数据包队列,这时只剩下基本数据块和分散数据块,由此调整它的数据块长度。
	接下来将IP分段队列的剩余分段数据包全部链人到第一个数据包的分段队列,它们成为了第一个数据包的分段数据包,使第一个数据包真正成为了主数据包。
	*/
	if (skb_shinfo(head)->frag_list) {//如果第一个数据包有分段数据包,就要将它的分段数据包转移到IP分段队列中
		struct sk_buff *clone;//克隆数据包指针
		int i, plen = 0;

		if ((clone = alloc_skb(0, GFP_ATOMIC)) == NULL)//分配克隆数据包、缓冲块和共享结构空间,注意缓冲块的长度为0,它只是起到转移点的作用
			goto out_nomem;
		clone->next = head->next;//将它链人到IP分段队列中,与第二个数据包建立关系
		head->next = clone;//与第一个数据包挂钩,成为第二个数据包
		skb_shinfo(clone)->frag_list = skb_shinfo(head)->frag_list;//继承第一个数据包的分段队列
		skb_shinfo(head)->frag_list = NULL;//第一个数据包与它的分段队列脱离关系
		for (i=0; i<skb_shinfo(head)->nr_frags; i++)//循环取得每一个分散数据块的长度
			plen += skb_shinfo(head)->frags[i].size;//累计分散数据块的总长度
		clone->len = clone->data_len = head->data_len - plen;//计算分段数据包的数据块总长度,记录到克隆数据包的数据块总长度中
		head->data_len -= clone->len;//设置第一个数据包的分散数据块总长度
		head->len -= clone->len;//调整第一个数据包的数据块总长度(只包括基本数据块和分散数据块的长度)
		clone->csum = 0;//初始化检验和
		clone->ip_summed = head->ip_summed;//继承第一个数据包的检验和标志
		atomic_add(clone->truesize, &qp->q.net->mem);//累加数据包占用内存计数
	}

	skb_shinfo(head)->frag_list = head->next;//把其他数据包当做第一个数据包的分段数剧包
	skb_push(head, head->data - skb_network_header(head));//调整第一个数据包的数据块起始地址，使它包含IP头部
	atomic_sub(head->truesize, &qp->q.net->mem);//递减数据包占用内存数
	//此后,head作为主数据包结构使用
	for (fp=head->next; fp; fp = fp->next) {//依次取得分段队列中的每一个数据包
		head->data_len += fp->len;//累加每一个数据块的长度
		head->len += fp->len;//主数据块的长度累加每一个数据块的长度
		if (head->ip_summed != fp->ip_summed)//对比检验和标志
			head->ip_summed = CHECKSUM_NONE;//标志不同就设置为无检验和标志
		else if (head->ip_summed == CHECKSUM_COMPLETE)//如果检验和完整
			head->csum = csum_add(head->csum, fp->csum);//重新调整检验和
		head->truesize += fp->truesize;//主数据包的实际长度累加每一个数据包的实际长度
		atomic_sub(fp->truesize, &qp->q.net->mem);//递减数据包占用内存数
	}

	head->next = NULL;//断开分段队列的联系
	head->dev = dev;//记录网络设备结构
	head->tstamp = qp->q.stamp;//记录时间戳

	iph = ip_hdr(head);//取得主数据包的IP头部结构
	iph->frag_off = 0;//清除分段标志,偏移位置为0
	iph->tot_len = htons(len);//记录主数据块的长度
	IP_INC_STATS_BH(IPSTATS_MIB_REASMOKS);//递增重组成功计数
	qp->q.fragments = NULL;//置空分段队列的数据包指针
	return 0;

out_nomem:
	LIMIT_NETDEBUG(KERN_ERR "IP: queue_glue: no memory for gluing "
			      "queue %p\n", qp);
	err = -ENOMEM;
	goto out_fail;
out_oversize:
	if (net_ratelimit())
		printk(KERN_INFO
			"Oversized IP packet from " NIPQUAD_FMT ".\n",
			NIPQUAD(qp->saddr));
out_fail:
	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);//递增失败计数器
	return err;
}

/* Process an incoming IP datagram fragment. */
int ip_defrag(struct sk_buff *skb, u32 user)
{
	struct ipq *qp;
	struct net *net;

	IP_INC_STATS_BH(IPSTATS_MIB_REASMREQDS);//递增计数

	net = skb->dev ? dev_net(skb->dev) : dev_net(skb->dst->dev);//获取网络空间
	/* Start by cleaning up the memory. */
	//查看分段数据包占用空间是否达到上限
	if (atomic_read(&net->ipv4.frags.mem) > net->ipv4.frags.high_thresh)
		ip_evictor(net);//清除网络空间内的分段队列

	/* Lookup (or create) queue header */
	if ((qp = ip_find(net, ip_hdr(skb), user)) != NULL) {//查找或者创建IP分段队列
		int ret;

		spin_lock(&qp->q.lock);//自旋锁

		ret = ip_frag_queue(qp, skb);//分段数据包人队，重组数据包

		spin_unlock(&qp->q.lock);
		ipq_put(qp);//递减IP分段队列的使用计数
		return ret;
	}

	IP_INC_STATS_BH(IPSTATS_MIB_REASMFAILS);//递增失败计数
	kfree_skb(skb);//释放数据包
	return -ENOMEM;
}

#ifdef CONFIG_SYSCTL
static int zero;

static struct ctl_table ip4_frags_ctl_table[] = {
	{
		.ctl_name	= NET_IPV4_IPFRAG_HIGH_THRESH,
		.procname	= "ipfrag_high_thresh",
		.data		= &init_net.ipv4.frags.high_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_IPV4_IPFRAG_LOW_THRESH,
		.procname	= "ipfrag_low_thresh",
		.data		= &init_net.ipv4.frags.low_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_IPV4_IPFRAG_TIME,
		.procname	= "ipfrag_time",
		.data		= &init_net.ipv4.frags.timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies
	},
	{
		.ctl_name	= NET_IPV4_IPFRAG_SECRET_INTERVAL,
		.procname	= "ipfrag_secret_interval",
		.data		= &ip4_frags.secret_interval,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies
	},
	{
		.procname	= "ipfrag_max_dist",
		.data		= &sysctl_ipfrag_max_dist,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1		= &zero
	},
	{ }
};

static int ip4_frags_ctl_register(struct net *net)
{
	struct ctl_table *table;
	struct ctl_table_header *hdr;

	table = ip4_frags_ctl_table;
	if (net != &init_net) {
		table = kmemdup(table, sizeof(ip4_frags_ctl_table), GFP_KERNEL);
		if (table == NULL)
			goto err_alloc;

		table[0].data = &net->ipv4.frags.high_thresh;
		table[1].data = &net->ipv4.frags.low_thresh;
		table[2].data = &net->ipv4.frags.timeout;
		table[3].mode &= ~0222;
		table[4].mode &= ~0222;
	}

	hdr = register_net_sysctl_table(net, net_ipv4_ctl_path, table);
	if (hdr == NULL)
		goto err_reg;

	net->ipv4.frags_hdr = hdr;
	return 0;

err_reg:
	if (net != &init_net)
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static void ip4_frags_ctl_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net->ipv4.frags_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipv4.frags_hdr);
	kfree(table);
}
#else
static inline int ip4_frags_ctl_register(struct net *net)
{
	return 0;
}

static inline void ip4_frags_ctl_unregister(struct net *net)
{
}
#endif

static int ipv4_frags_init_net(struct net *net)
{
	/*
	 * Fragment cache limits. We will commit 256K at one time. Should we
	 * cross that limit we will prune down to 192K. This should cope with
	 * even the most extreme cases without allowing an attacker to
	 * measurably harm machine performance.
	 */
	net->ipv4.frags.high_thresh = 256 * 1024;
	net->ipv4.frags.low_thresh = 192 * 1024;
	/*
	 * Important NOTE! Fragment queue must be destroyed before MSL expires.
	 * RFC791 is wrong proposing to prolongate timer each fragment arrival
	 * by TTL.
	 */
	net->ipv4.frags.timeout = IP_FRAG_TIME;

	inet_frags_init_net(&net->ipv4.frags);

	return ip4_frags_ctl_register(net);
}

static void ipv4_frags_exit_net(struct net *net)
{
	ip4_frags_ctl_unregister(net);
	inet_frags_exit_net(&net->ipv4.frags, &ip4_frags);
}

static struct pernet_operations ip4_frags_ops = {
	.init = ipv4_frags_init_net,
	.exit = ipv4_frags_exit_net,
};

void __init ipfrag_init(void)
{
	register_pernet_subsys(&ip4_frags_ops);
	ip4_frags.hashfn = ip4_hashfn;
	ip4_frags.constructor = ip4_frag_init;
	ip4_frags.destructor = ip4_frag_free;
	ip4_frags.skb_free = NULL;
	ip4_frags.qsize = sizeof(struct ipq);
	ip4_frags.match = ip4_frag_match;
	ip4_frags.frag_expire = ip_expire;
	ip4_frags.secret_interval = 10 * 60 * HZ;
	inet_frags_init(&ip4_frags);
}

EXPORT_SYMBOL(ip_defrag);
