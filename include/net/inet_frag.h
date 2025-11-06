#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

struct netns_frags {//网络空间的分段管理结构
	int			nqueues;//队列数
	atomic_t		mem;//内存使用计数
	struct list_head	lru_list;//老化队列

	/* sysctls */
	int			timeout;//超时时间
	int			high_thresh;//内存使用上线
	int			low_thresh;//内存使用下线
};

struct inet_frag_queue {//INET 分段队列头结构
	struct hlist_node	list;//哈希节点,链人INET分段管理结构的哈希队列
	struct netns_frags	*net;//隶属的网络空间分段管理结构
	struct list_head	lru_list;   /* lru list member 老化队列链头,链入网络空间分段管理结构的老化队列*/
	spinlock_t		lock;//锁
	atomic_t		refcnt;//计数器
	struct timer_list	timer;      /* when will this queue expire?队列计时器 */
	struct sk_buff		*fragments; /* list of received fragments 分段数据包队列 */
	ktime_t			stamp;//时间戳
	int			len;        /* total length of orig datagram 数据包结束位置(offset+len) */
	int			meat; //与原数据包长度的差距,如果与原数据包长度相同代表接收完成
	__u8			last_in;    /* first/last segment arrived? 是否接收了第一个和最后一个分段数据包*/

#define INET_FRAG_COMPLETE	4
#define INET_FRAG_FIRST_IN	2
#define INET_FRAG_LAST_IN	1
};

#define INETFRAGS_HASHSZ		64

struct inet_frags {//INET的分段管理结构
	struct hlist_head	hash[INETFRAGS_HASHSZ];//hash队列
	rwlock_t		lock;//锁
	u32			rnd;//随机数
	int			qsize;//队列结构的长度
	int			secret_interval;//定时间隔时间
	struct timer_list	secret_timer;//定时器

	unsigned int		(*hashfn)(struct inet_frag_queue *);//hash计算函数
	void			(*constructor)(struct inet_frag_queue *q,
						void *arg);//构造函数
	void			(*destructor)(struct inet_frag_queue *);//析构函数
	void			(*skb_free)(struct sk_buff *);//释放数据包函数
	int			(*match)(struct inet_frag_queue *q,
						void *arg);//分段匹配函数
	void			(*frag_expire)(unsigned long data);//分段队列过期处理函数
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

void inet_frags_init_net(struct netns_frags *nf);
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);
void inet_frag_destroy(struct inet_frag_queue *q,
				struct inet_frags *f, int *work);
int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f);
struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash);

static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

#endif
