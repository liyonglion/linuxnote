/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

struct request_sock_ops {
	int		family;//所属协议族
	int		obj_size;//连接请求块的大小
	struct kmem_cache	*slab;//连接请求的高速缓存
	//SYN+ACK段重传时调用该函数
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req);
	//发送ack段时调用该函数				   
	void		(*send_ack)(struct sk_buff *skb,
				    struct request_sock *req);
	//发送RST段时调用该函数				
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	//析构函数				  
	void		(*destructor)(struct request_sock *req);
};

/* struct request_sock - mini sock to represent a connection request
在完成三次握手前，连接都用request_sock结构表示，为了减小内存的占用
 */
struct request_sock {//如果是接收握手请求，那么会建立request_sock 做为一个mini sock，request_sock_ops操作函数则在proto结构体中初始化。tcp协议的request_sock_ops为tcp_request_sock_ops，此为变量名。
	//和其它struct request_sock 对象形成链表
	struct request_sock		*dl_next; /* Must be first member! */
	//syn段中的客户端通告的MSS
	u16				mss;
	//syn+ack 段已经重传的次数，初始化为0
	u8				retrans;
	u8				cookie_ts; /* syncookie: encode tcpopts in timestamp */
	/* The following two fields can be easily recomputed I think -AK */
	u32				window_clamp; /* window clamp at creation time 发送窗口大小*/
	u32				rcv_wnd;	  /* rcv_wnd offered first time接收窗口大小 */
	u32				ts_recent;
	//SYN+ACK段的超时时间
	unsigned long			expires;
	//指向tcp_request_sock_ops，该函数集用于处理第三次握手的ACK段以及后续accept过程中struct tcp_sock对象的创建
	const struct request_sock_ops	*rsk_ops;
	//连接建立前无效，建立后指向创建的tcp_sock结构
	struct sock			*sk;
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
struct listen_sock {
	//其取值为nr_table_entries以2为底的对数
	u8			max_qlen_log;
	/* 3 bytes hole, try to use */
	//当前syn_table哈希表中套接字的数据，即有多少个半连接套接字
	int			qlen;
	//服务器端会超时重传syn+ack段，该变量记录了那些还未重传过SYN+ACK段的套接字个数
	int			qlen_young;
	
	int			clock_hand;
	//用于随机访问listen_opt哈希表时计算hash值
	u32			hash_rnd;
	//syn_table哈希表的桶大小，该值和listen系统调用的backlog参数有关
	u32			nr_table_entries;
	//半连接套接字hash表，管理的元素就是连接请求块
	struct request_sock	*syn_table[0];
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
struct request_sock_queue {
	//head和tail用于维护已经完成三次握手、等待用户程序accept的套接字，即全连接队列
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;
	//用于同步对listen_opt的操作
	rwlock_t		syn_wait_lock;
	//于TCP选项TCP_DEFER_ACCEPT相关
	u8			rskq_defer_accept;
	/* 3 bytes hole, try to pack */
	/* 已经收到syn，但是尚未完成三次握手的套接字保存在这个结构中，即半连接队列*/
	struct listen_sock	*listen_opt;
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

extern void __reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	BUG_TRAP(req != NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
	struct request_sock *req = reqsk_queue_remove(queue);
	struct sock *child = req->sk;

	BUG_TRAP(child != NULL);

	sk_acceptq_removed(parent);//从全连接队列中删除
	__reqsk_free(req);//释放request_sock结构
	return child;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
