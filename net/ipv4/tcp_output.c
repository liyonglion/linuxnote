/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp_output.c,v 1.146 2002/02/01 22:01:04 davem Exp $
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#include <net/tcp.h>

#include <linux/compiler.h>
#include <linux/module.h>

/* People can turn this off for buggy TCP's found in printers etc. */
int sysctl_tcp_retrans_collapse __read_mostly = 1;

/* People can turn this on to  work with those rare, broken TCPs that
 * interpret the window field as a signed quantity.
 */
int sysctl_tcp_workaround_signed_windows __read_mostly = 0;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_tcp_tso_win_divisor __read_mostly = 3;

int sysctl_tcp_mtu_probing __read_mostly = 0;
int sysctl_tcp_base_mss __read_mostly = 512;//search_low的初始值，用于发现路径MTU (MTU探测)。如果启用了MTU探测，则这是连接使用的初始MSS。

/* By default, RFC2861 behavior.  */
int sysctl_tcp_slow_start_after_idle __read_mostly = 1;//会在连接空闲一定时间后重置连接的拥塞窗口。在连接空闲的同时，网络状况也可能发生了变化，为了避免拥塞，理应将拥塞窗口重置回“安全的”默认值。

static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;//发送数据包总数
	//将下一个发送数据包记录到发送头中,准备发送它
	tcp_advance_send_head(sk, skb);
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;//记录下一个发送的序列号

	/* Don't override Nagle indefinately with F-RTO */
	if (tp->frto_counter == 2)
		tp->frto_counter = 3;

	tp->packets_out += tcp_skb_pcount(skb);//累计发送数据包总数
	if (!prior_packets)//如果没有发送成功就重新设置发送定时器
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
}

/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!before(tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst && dst_metric(dst, RTAX_ADVMSS) < mss) {
		mss = dst_metric(dst, RTAX_ADVMSS);
		tp->advmss = mss;
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void tcp_cwnd_restart(struct sock *sk, struct dst_entry *dst)
{
	struct tcp_sock *tp = tcp_sk(sk);
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;

	tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	tp->snd_ssthresh = tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

static void tcp_event_data_sent(struct tcp_sock *tp,
				struct sk_buff *skb, struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_time_stamp;

	if (sysctl_tcp_slow_start_after_idle &&
	    (!tp->packets_out && (s32)(now - tp->lsndtime) > icsk->icsk_rto))
		tcp_cwnd_restart(sk, __sk_dst_get(sk));//重启拥塞控制。在连接空闲的同时，网络状况也可能发生了变化，为了避免拥塞，理应将拥塞窗口重置回“安全的”默认值。

	tp->lsndtime = now;

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	if ((u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		icsk->icsk_ack.pingpong = 1;
}

static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts)
{
	tcp_dec_quickack_mode(sk, pkts);
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale)
{//初始化滑动窗口
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss;

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sysctl_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = space;

	(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window
		 * See RFC1323 for an explanation of the limit to 14
		 */
		space = max_t(u32, sysctl_tcp_rmem[2], sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}

	/* Set initial window to value enough for senders,
	 * following RFC2414. Senders, not following this RFC,
	 * will be satisfied with 2.
	 */
	if (mss > (1 << *rcv_wscale)) {
		int init_cwnd = 4;
		if (mss > 1460 * 3)
			init_cwnd = 2;
		else if (mss > 1460)
			init_cwnd = 3;
		if (*rcv_wnd > init_cwnd * mss)
			*rcv_wnd = init_cwnd * mss;
	}

	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
}

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale && sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;

	return new_win;
}

static inline void TCP_ECN_send_synack(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_ECE;
}
//这里根据内核的 sysctl_tcp_ecn 判断是否启用ECN 来增加数据包控制信息标志 TCPCBFLAGECE和TCPCB FLAG_CWR,
//它们用来表明客户端具有ECN功能,这是遵循RFC793标准设置的。
static inline void TCP_ECN_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->ecn_flags = 0;
	if (sysctl_tcp_ecn) {
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_ECE | TCPCB_FLAG_CWR;
		tp->ecn_flags = TCP_ECN_OK;
	}
}

static __inline__ void
TCP_ECN_make_synack(struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

static inline void TCP_ECN_send(struct sock *sk, struct sk_buff *skb,
				int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				tcp_hdr(skb)->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			tcp_hdr(skb)->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->csum = 0;

	TCP_SKB_CB(skb)->flags = flags;//设置标志
	TCP_SKB_CB(skb)->sacked = 0;//SACK状态标志

	skb_shinfo(skb)->gso_segs = 1;//分段数据包总数，代表只有一个数据包
	skb_shinfo(skb)->gso_size = 0;//分段数据包长度
	skb_shinfo(skb)->gso_type = 0;//分段数据包类型

	TCP_SKB_CB(skb)->seq = seq;//保存计算出来的seq
	if (flags & (TCPCB_FLAG_SYN | TCPCB_FLAG_FIN))//syn或者FIN都需要seq号加1
		seq++;//对于SYN/FIN,seq号加1
	TCP_SKB_CB(skb)->end_seq = seq;
}

static void tcp_build_and_update_options(__be32 *ptr, struct tcp_sock *tp,
					 __u32 tstamp, __u8 **md5_hash)
{
	if (tp->rx_opt.tstamp_ok) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_TIMESTAMP << 8) |
			       TCPOLEN_TIMESTAMP);
		*ptr++ = htonl(tstamp);
		*ptr++ = htonl(tp->rx_opt.ts_recent);
	}
	if (tp->rx_opt.eff_sacks) {
		struct tcp_sack_block *sp = tp->rx_opt.dsack ? tp->duplicate_sack : tp->selective_acks;
		int this_sack;

		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (tp->rx_opt.eff_sacks *
						     TCPOLEN_SACK_PERBLOCK)));

		for (this_sack = 0; this_sack < tp->rx_opt.eff_sacks; this_sack++) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}

		if (tp->rx_opt.dsack) {
			tp->rx_opt.dsack = 0;
			tp->rx_opt.eff_sacks--;
		}
	}
#ifdef CONFIG_TCP_MD5SIG
	if (md5_hash) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) |
			       TCPOLEN_MD5SIG);
		*md5_hash = (__u8 *)ptr;
	}
#endif
}

/* Construct a tcp options header for a SYN or SYN_ACK packet.
 * If this is every changed make sure to change the definition of
 * MAX_SYN_SIZE to match the new maximum number of options that you
 * can generate.
 *
 * Note - that with the RFC2385 TCP option, we make room for the
 * 16 byte MD5 hash. This will be filled in later, so the pointer for the
 * location to be filled is passed back up.
 */
static void tcp_syn_build_options(__be32 *ptr, int mss, int ts, int sack,
				  int offer_wscale, int wscale, __u32 tstamp,
				  __u32 ts_recent, __u8 **md5_hash)
{
	/* We always get an MSS option.
	 * The option bytes which will be seen in normal data
	 * packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so
	 * that calculations in tcp_sendmsg are simpler etc.
	 * So account for this fact here if necessary.  If we
	 * don't do this correctly, as a receiver we won't
	 * recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK
	 * rules correctly.
	 * SACKs don't matter, we never delay an ACK when we
	 * have any of those going out.
	 */
	*ptr++ = htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mss);
	if (ts) {
		if (sack)
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		else
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		*ptr++ = htonl(tstamp);		/* TSVAL */
		*ptr++ = htonl(ts_recent);	/* TSECR */
	} else if (sack)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	if (offer_wscale)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       (wscale));
#ifdef CONFIG_TCP_MD5SIG
	/*
	 * If MD5 is enabled, then we set the option, and include the size
	 * (always 18). The actual MD5 hash is added just before the
	 * packet is sent.
	 */
	if (md5_hash) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) |
			       TCPOLEN_MD5SIG);
		*md5_hash = (__u8 *)ptr;
	}
#endif
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	int tcp_header_size;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *md5;
	__u8 *md5_hash_location;
#endif
	struct tcphdr *th;
	int sysctl_flags;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));

	/* If congestion control is doing timestamping, we must
	 * take such a timestamp before we potentially clone/copy.
	 */
	if (icsk->icsk_ca_ops->flags & TCP_CONG_RTT_STAMP)
		__net_timestamp(skb);//记录当前时间，为了处理拥塞时使用

	if (likely(clone_it)) {//是否使用克隆数据包
		if (unlikely(skb_cloned(skb)))//克隆数据包是否可用
			skb = pskb_copy(skb, gfp_mask);//创建一个数据包，并复制内容
		else
			skb = skb_clone(skb, gfp_mask);//使用克隆数据包
		if (unlikely(!skb))
			return -ENOBUFS;
	}

	inet = inet_sk(sk);//获取inet_sock指针
	tp = tcp_sk(sk);//获取tcp_sock指针
	tcb = TCP_SKB_CB(skb);//获取TCP控制块结构指针
	tcp_header_size = tp->tcp_header_len;//获取tcp包头部长度

#define SYSCTL_FLAG_TSTAMPS	0x1
#define SYSCTL_FLAG_WSCALE	0x2
#define SYSCTL_FLAG_SACK	0x4

	sysctl_flags = 0;//控制标志
	if (unlikely(tcb->flags & TCPCB_FLAG_SYN)) {//是否设置了SYN标志，SYN包需要带特有的一些选项头，因此要计算tcp头部长度
		tcp_header_size = sizeof(struct tcphdr) + TCPOLEN_MSS;//修改tcp头部长度，增加MSS选项
		if (sysctl_tcp_timestamps) {//是否支持TCP时间戳
			tcp_header_size += TCPOLEN_TSTAMP_ALIGNED;//增加记录时间戳长度
			sysctl_flags |= SYSCTL_FLAG_TSTAMPS;//增加时间戳标志
		}
		if (sysctl_tcp_window_scaling) {//是否支持窗口缩放
			tcp_header_size += TCPOLEN_WSCALE_ALIGNED;//增加记录窗口缩放长度
			sysctl_flags |= SYSCTL_FLAG_WSCALE;//增加窗口缩放标志
		}
		if (sysctl_tcp_sack) {//是否支持SACK
			sysctl_flags |= SYSCTL_FLAG_SACK;//增加SACK标志
			if (!(sysctl_flags & SYSCTL_FLAG_TSTAMPS))//如果未设置时间戳标志，增加SACK标志
				tcp_header_size += TCPOLEN_SACKPERM_ALIGNED;//增加SACK长度
		}
	} else if (unlikely(tp->rx_opt.eff_sacks)) {//如果没有指定SACK的总长度
		/* A SACK is 2 pad bytes, a 2 byte header, plus
		 * 2 32-bit sequence numbers for each SACK block.
		 */
		tcp_header_size += (TCPOLEN_SACK_BASE_ALIGNED +
				    (tp->rx_opt.eff_sacks *
				     TCPOLEN_SACK_PERBLOCK));//计算并增加SACK总长度
	}

	if (tcp_packets_in_flight(tp) == 0)//是否有包处于发送途中，没有说明刚开始发包，需要初始化拥塞窗口状态
		tcp_ca_event(sk, CA_EVENT_TX_START);//调用拥塞窗口事件函数

#ifdef CONFIG_TCP_MD5SIG
	/*
	 * Are we doing MD5 on this segment? If so - make
	 * room for it.
	 */
	md5 = tp->af_specific->md5_lookup(sk, sk);
	if (md5)
		tcp_header_size += TCPOLEN_MD5SIG_ALIGNED;
#endif

	skb_push(skb, tcp_header_size);//调整数据块起始地址，向下延申，开辟TCP头部空间
	skb_reset_transport_header(skb);//数据包记录当前的TCP头部指针
	skb_set_owner_w(skb, sk);//建立与sock的关联，设置析构函数

	/* Build TCP header and checksum it. */
	th = tcp_hdr(skb);//指向数据块中的TCP头部
	th->source		= inet->sport;//记录源端口
	th->dest		= inet->dport;//记录目标端口
	th->seq			= htonl(tcb->seq);//记录发送序号
	th->ack_seq		= htonl(tp->rcv_nxt);//记录ack序号
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->flags);//记录头部长度和标识
	//FIXME： 如何计算窗口大小
	if (unlikely(tcb->flags & TCPCB_FLAG_SYN)) {//是否设置syn标志
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));//设置窗口大小
	} else {
		th->window	= htons(tcp_select_window(sk));//
	}
	th->check		= 0;//设置校验和
	th->urg_ptr		= 0;//设置紧急指针

	if (unlikely(tp->urg_mode &&
		     between(tp->snd_up, tcb->seq + 1, tcb->seq + 0xFFFF))) {
		th->urg_ptr		= htons(tp->snd_up - tcb->seq);
		th->urg			= 1;
	}
	/*
	调用 tcp_syn_build_options()函数以及 tep_build_and_update_options()函数设置 TCP选项,这两个函数都是按照RFC2385协议来设置或者更新选项内容
	*/
	if (unlikely(tcb->flags & TCPCB_FLAG_SYN)) {//是否设置了SYN标志
		tcp_syn_build_options((__be32 *)(th + 1),
				      tcp_advertise_mss(sk),//使用对外公开的MSS
				      (sysctl_flags & SYSCTL_FLAG_TSTAMPS),
				      (sysctl_flags & SYSCTL_FLAG_SACK),
				      (sysctl_flags & SYSCTL_FLAG_WSCALE),
				      tp->rx_opt.rcv_wscale,
				      tcb->when,
				      tp->rx_opt.ts_recent,

#ifdef CONFIG_TCP_MD5SIG
				      md5 ? &md5_hash_location :
#endif
				      NULL);//初始化并写入SYN选项
	} else {//常规数据报文进行填充tcp选项
		tcp_build_and_update_options((__be32 *)(th + 1),
					     tp, tcb->when,
#ifdef CONFIG_TCP_MD5SIG
					     md5 ? &md5_hash_location :
#endif
					     NULL);
		TCP_ECN_send(sk, skb, tcp_header_size);//设置CWR拥塞减少标志ece提醒标志
	}

#ifdef CONFIG_TCP_MD5SIG
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		tp->af_specific->calc_md5_hash(md5_hash_location,
					       md5,
					       sk, NULL, NULL,
					       tcp_hdr(skb),
					       sk->sk_protocol,
					       skb->len);
	}
#endif
	//tcp_v4_init_sock()函数中被挂入了ipv4_specific 结构。计算IP头部校验和
	icsk->icsk_af_ops->send_check(sk, skb->len, skb);//计算并记录检验和。此处为：tcp_v4_send_check()

	if (likely(tcb->flags & TCPCB_FLAG_ACK))//如果设置了ACK标志
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb));//调整快速ACK数值

	if (skb->len != tcp_header_size)//说明包含待发送的数据
		tcp_event_data_sent(tp, skb, sk);//复位阻塞窗口
	//检查发送序号，递增发送计数
	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_INC_STATS(TCP_MIB_OUTSEGS);

	err = icsk->icsk_af_ops->queue_xmit(skb, 0);//调用连接函数表的发送函数，queue_xmit 为ip_queue_xmit()函数
	if (likely(err <= 0))
		return err;

	tcp_enter_cwr(sk, 1);//检查阻塞状态,设置慢启动和阻塞窗口等内容

	return net_xmit_eval(err);//确定返回值,拥塞返回0

#undef SYSCTL_FLAG_TSTAMPS
#undef SYSCTL_FLAG_WSCALE
#undef SYSCTL_FLAG_SACK
}

/* This routine just queue's the buffer
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

static void tcp_set_skb_tso_segs(struct sock *sk, struct sk_buff *skb,
				 unsigned int mss_now)
{
	//如果该skb数据量不足一个MSS，或者根本就不支持GSO，那么就是一个段
	if (skb->len <= mss_now || !sk_can_gso(sk)) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->gso_segs = 1;//初始化分段数量
		skb_shinfo(skb)->gso_size = 0;;//初始化分段长度
		skb_shinfo(skb)->gso_type = 0;//初始化分段类型
	} else {//计算要切割的段数，就是skb->len除以MSS，结果向上取整
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);//计算分段数量
		skb_shinfo(skb)->gso_size = mss_now;//MSS作为分段长度
		skb_shinfo(skb)->gso_type = sk->sk_gso_type;//分段类型 SKB_GSO_TCPV4
	}
}

/* When a modification to fackets out becomes necessary, we need to check
 * skb is counted to fackets_out or not.
 */
static void tcp_adjust_fackets_out(struct sock *sk, struct sk_buff *skb,
				   int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->sacked_out || tcp_is_reno(tp))
		return;

	if (after(tcp_highest_sack_seq(tp), TCP_SKB_CB(skb)->seq))
		tp->fackets_out -= decr;
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
		 unsigned int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u16 flags;

	BUG_ON(len > skb->len);

	tcp_clear_retrans_hints_partial(tp);//复位重发队列
	nsize = skb_headlen(skb) - len;//需要分段的数据块长度
	if (nsize < 0)//如果分段数据块长度小于0
		nsize = 0;//设置分段数据块长度为0

	if (skb_cloned(skb) &&//如果数据包是克隆的
	    skb_is_nonlinear(skb) && //并且有分散数据块
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))//重新分配数据包结构，复制数据块和分散数据块
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);//分配新数据包结构和共享数据结构，按分段数据块长度分配缓冲块
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */

	sk->sk_wmem_queued += buff->truesize;//累加sock 内存计数器
	sk_mem_charge(sk, buff->truesize);//递减可用内存计数器
	nlen = skb->len - len - nsize;//计算超出长度
	buff->truesize += nlen;//累加新数据包的实际尺寸
	skb->truesize -= nlen;//递减原数据包的实际尺寸

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;//设置新数据包的发送序号
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;//设置它的结束序号
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;//调整原数据包的结束序号

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;//获取原数据包的控制标志
	TCP_SKB_CB(skb)->flags = flags & ~(TCPCB_FLAG_FIN | TCPCB_FLAG_PSH);
	TCP_SKB_CB(buff)->flags = flags;//设置控制标志到新数据包中
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;//继承原数据包的 SACK
	//如果原数据包没有分散数据块，并且没有设置检验和
	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
						       skb_put(buff, nsize),
						       nsize, 0);//复制数据到新数据包的数据块中并计算检验和

		skb_trim(skb, len);//设置原数据包的数据块长度和结束地址,使数据块符合指定长度

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);//重新计算检验和
	} else {//如果有分散数据块
		skb->ip_summed = CHECKSUM_PARTIAL;//设置检验和标志
		skb_split(skb, buff, len);//分隔、转嫁超出部分到新数据包
	}

	buff->ip_summed = skb->ip_summed;//继承原数据包的检验和标志

	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;//控制结构继承时间戳
	buff->tstamp = skb->tstamp;//继承原数据包时间戳

	old_factor = tcp_skb_pcount(skb);//获取原数据包的分段数据包数量

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);//重新设置原数据包的分段信息
	tcp_set_skb_tso_segs(sk, buff, mss_now);//设置新数据包的分段信息

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {//检查发送序列号
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);//分段前后的数据包总差数

		tp->packets_out -= diff;//调整发送数据包计数器

		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
			tp->sacked_out -= diff;//调整SACK数据包计数器
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
			tp->retrans_out -= diff;//调整重发数据包计数器

		if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
			tp->lost_out -= diff;//调整丢失数据包计数器

		/* Adjust Reno SACK estimate. */
		if (tcp_is_reno(tp) && diff > 0) {//检查对方的SACK
			tcp_dec_pcount_approx_int(&tp->sacked_out, diff);//调整发送数据包计数
			tcp_verify_left_out(tp);//检查是否丢失数据包
		}
		tcp_adjust_fackets_out(sk, skb, diff);//调整 FACK数据包计数器
	}

	/* Link BUFF into the send queue. */
	skb_header_release(buff);//设置新数据包没有头部标志
	tcp_insert_write_queue_after(skb, buff, sk);//将新数据包链人发送队列

	return 0;
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static void __pskb_trim_head(struct sk_buff *skb, int len)
{
	int i, k, eat;

	eat = len;//需要移除的数据长度
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {//遍历分散数据块
		if (skb_shinfo(skb)->frags[i].size <= eat) {//如果数据块长度小于需要移除的数据长度
			put_page(skb_shinfo(skb)->frags[i].page);//释放数据块
			eat -= skb_shinfo(skb)->frags[i].size;//调整需要移除数据块长度
		} else {//需要移除的数据块长度小于当前分散数据块长度，需要调整数据块偏移和长度
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];//调整数据块索引，之前的数据块都已经被拷贝了
			if (eat) {//如果需要移除的数据块长度大于0
				skb_shinfo(skb)->frags[k].page_offset += eat;//调整数据块偏移
				skb_shinfo(skb)->frags[k].size -= eat;//调整数据块长度
				eat = 0;//移除数据块长度为0，循环继续，目的是为了统计剩余分散数据块数量
			}
			k++;//剩余分散数据块数量
		}
	}
	skb_shinfo(skb)->nr_frags = k;//调整分散数据块数量

	skb_reset_tail_pointer(skb);//调整非线性数据块偏移
	skb->data_len -= len;//调整非线性数据块长度
	skb->len = skb->data_len;//调整整体数据块长度
}

int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* If len == headlen, we avoid __skb_pull to preserve alignment. */
	if (unlikely(len < skb_headlen(skb)))
		__skb_pull(skb, len);
	else
		__pskb_trim_head(skb, len - skb_headlen(skb));

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);

	/* Any change of skb->len requires recalculation of tso
	 * factor and mss.
	 */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(sk, skb, tcp_current_mss(sk, 1));

	return 0;
}

/* Not accounting for SACKs here. */
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);//MSS= MTU - TCP头长度 - 网络头部长度

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)//检查MSS 是否超过对端的MSS。也就是说握手过程两端会协商处使用最小的MSS进行发送
		mss_now = tp->rx_opt.mss_clamp;//使用对端的MSS

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;//减去IP选项头长度

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)//最小值为48字节
		mss_now = 48;

	/* Now subtract TCP options size, not including SACKs */
	mss_now -= tp->tcp_header_len - sizeof(struct tcphdr);//减去TCP选项长度

	return mss_now;
}

/* Inverse of above */
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;

	mtu = mss +
	      tp->tcp_header_len + //TCP头长度
	      icsk->icsk_ext_hdr_len + //IP选项头长度
	      icsk->icsk_af_ops->net_header_len;//网络头部长度

	return mtu;
}
/*这个函数负责MTU探测的初始化，设置当前探测的上限、下限等。这里的下限比较明确，是通过系统设置的最小MSS值（默认为512字节）转换为MTU（加上40字节）。
上限则是由rx_opt（接收的对端选项）的mss_clamp决定的。对于主动连接来说，其值为MSS的默认值（目前是536字节，在RFC1122和RFC2581中定义）。*/
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_mtup.enabled = sysctl_tcp_mtu_probing > 1;//MTU启动标志位;0表示不开启，1 表示只有在黑洞情况下开启探测；2 表示开启探测
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) + //这里的mss_clamp为对端的MSS，初始化未536
			       icsk->icsk_af_ops->net_header_len;//MTU的搜索范围，上限与下限。初始化上限为对端mss+tcp头头+网络头部，若启动了MTU探测，会在tcp_mtu_probe()函数中进行调整。这里初始化是最小值
	//根据MSS计算MTU			   
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, sysctl_tcp_base_mss);//sysctl_tcp_base_mss初始值为512，如果启用了MTU探测，则这是连接使用的初始MSS。由sysctl->net.ipv4.tcp_base_mss赋值
	icsk->icsk_mtup.probe_size = 0;//当前探测值
}

/* Bound MSS / TSO packet size with the half of the window */
static int tcp_bound_to_half_wnd(struct tcp_sock *tp, int pktsize)
{
	//max_window为当前已知接收方所拥有的最大窗口值，这里如果参数pktsize超过了接收窗口的一半，则调整其大小最大为接收窗口的一半
	if (tp->max_window && pktsize > (tp->max_window >> 1))
		return max(tp->max_window >> 1, 68U - tp->tcp_header_len);
	else
		return pktsize;
}

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	if (icsk->icsk_mtup.search_high > pmtu)//检查MTU最大值是否超过指定的MTU值
		icsk->icsk_mtup.search_high = pmtu;//修改为指定的MTU值

	mss_now = tcp_mtu_to_mss(sk, pmtu);//根据mtu计算mss
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);//调整MSS为窗口半值

	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu;//记录MTU值
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));//根据MTU最小值调整MSS
	tp->mss_cache = mss_now;//记录MSS值

	return mss_now;
}

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 *
 * LARGESEND note: !urg_mode is overkill, only frames up to snd_up
 * cannot be large. However, taking into account rare use of URG, this
 * is not a big flaw.
 */
unsigned int tcp_current_mss(struct sock *sk, int large_allowed)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	u16 xmit_size_goal;
	int doing_tso = 0;

	mss_now = tp->mss_cache;//缓存的MSS值，初始值为536

	if (large_allowed && sk_can_gso(sk) && !tp->urg_mode)
		doing_tso = 1;

	if (dst) {
		u32 mtu = dst_mtu(dst);//获取路由项里面的MTU值
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);//使用路由指定的MTU计算MSS
	}

	if (tp->rx_opt.eff_sacks)
		mss_now -= (TCPOLEN_SACK_BASE_ALIGNED +
			    (tp->rx_opt.eff_sacks * TCPOLEN_SACK_PERBLOCK));//减去sack选项大小

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk))
		mss_now -= TCPOLEN_MD5SIG_ALIGNED;
#endif
	//xmit_size_goal初始化为MSS
	xmit_size_goal = mss_now;
	//如果支持TSO，则xmit_size_goal可以更大
	if (doing_tso) {//使用TSO功能
		//计算分段大小
		xmit_size_goal = ((sk->sk_gso_max_size - 1) - //GSO最大分段大小
				  inet_csk(sk)->icsk_af_ops->net_header_len - //网络头部长度
				  inet_csk(sk)->icsk_ext_hdr_len - //可选IP头部长度
				  tp->tcp_header_len);//tcp头长度
		//分段大小不能超过最大窗口的一半
		xmit_size_goal = tcp_bound_to_half_wnd(tp, xmit_size_goal);
		xmit_size_goal -= (xmit_size_goal % mss_now);//分段大小必须时整除mss_now
	}
	tp->xmit_size_goal = xmit_size_goal;//计算分段大小

	return mss_now;
}

/* Congestion window validation. (RFC2861) */
static void tcp_cwnd_validate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->packets_out >= tp->snd_cwnd) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_time_stamp;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

		if (sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_time_stamp - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto)
			tcp_cwnd_application_limited(sk);
	}
}

/* Returns the portion of skb which can be sent right away without
 * introducing MSS oddities to segment boundaries. In rare cases where
 * mss_now != mss_cache, we will request caller to create a small skb
 * per input skb which could be mostly avoided here (if desired).
 *
 * We explicitly want to create a request for splitting write queue tail
 * to a small skb for Nagle purposes while avoiding unnecessary modulos,
 * thus all the complexity (cwnd_len is always MSS multiple which we
 * return whenever allowed by the other factors). Basically we need the
 * modulo only when the receiver window alone is the limiting factor or
 * when we would be allowed to send the split-due-to-Nagle skb fully.
 */
static unsigned int tcp_mss_split_point(struct sock *sk, struct sk_buff *skb,
					unsigned int mss_now, unsigned int cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 needed, window, cwnd_len;

	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	cwnd_len = mss_now * cwnd;

	if (likely(cwnd_len <= window && skb != tcp_write_queue_tail(sk)))
		return cwnd_len;

	needed = min(skb->len, window);

	if (cwnd_len <= needed)
		return cwnd_len;

	return needed - needed % mss_now;
}

/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int tcp_cwnd_test(struct tcp_sock *tp,
					 struct sk_buff *skb)
{
	u32 in_flight, cwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN) && //检查FIN标志
	    tcp_skb_pcount(skb) == 1)//检查数据包的分段数量
		return 1;

	in_flight = tcp_packets_in_flight(tp);//计算处于发送过程的数据包数量
	cwnd = tp->snd_cwnd;//发送阻塞窗口
	if (in_flight < cwnd)//如果发送过程的数量在阻塞窗口内
		return (cwnd - in_flight);//返回可发送数量

	return 0;
}

/* This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int tcp_init_tso_segs(struct sock *sk, struct sk_buff *skb,
			     unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);//获取数据包共享结构记录的分段数量
	//如果没有分段,或者有多个分段但是分段长度不等于MSS，说明调整过MSS，需要重新计算
	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_set_skb_tso_segs(sk, skb, mss_now);//重新设置数据包的分段信息
		tso_segs = tcp_skb_pcount(skb);//重新获取分段数量
	}
	return tso_segs;//返回分段数量
}

static inline int tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml,tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Return 0, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized.
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_NODELAY was set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static inline int tcp_nagle_check(const struct tcp_sock *tp,
				  const struct sk_buff *skb,
				  unsigned mss_now, int nonagle)
{
	return (skb->len < mss_now &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out && tcp_minshall_check(tp))));
}

/* Return non-zero if the Nagle test allows this packet to be
 * sent now.
 */
static inline int tcp_nagle_test(struct tcp_sock *tp, struct sk_buff *skb,
				 unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return 1;

	/* Don't use the nagle rule for urgent data (or for the final FIN).
	 * Nagle can be ignored during F-RTO too (see RFC4138).
	 */
	if (tp->urg_mode || (tp->frto_counter == 2) ||
	    (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN))
		return 1;

	if (!tcp_nagle_check(tp, skb, cur_mss, nonagle))
		return 1;

	return 0;
}

/* Does at least the first segment of SKB fit into the send window? */
static inline int tcp_snd_wnd_test(struct tcp_sock *tp, struct sk_buff *skb,
				   unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	return !after(end_seq, tcp_wnd_end(tp));
}

/* This checks if the data bearing packet SKB (usually tcp_send_head(sk))
 * should be put on the wire right now.  If so, it returns the number of
 * packets allowed by the congestion window.
 */
static unsigned int tcp_snd_test(struct sock *sk, struct sk_buff *skb,
				 unsigned int cur_mss, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cwnd_quota;

	tcp_init_tso_segs(sk, skb, cur_mss);

	if (!tcp_nagle_test(tp, skb, cur_mss, nonagle))
		return 0;

	cwnd_quota = tcp_cwnd_test(tp, skb);
	if (cwnd_quota && !tcp_snd_wnd_test(tp, skb, cur_mss))
		cwnd_quota = 0;

	return cwnd_quota;
}

int tcp_may_send_now(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_send_head(sk);

	return (skb &&
		tcp_snd_test(sk, skb, tcp_current_mss(sk, 1),
			     (tcp_skb_is_last(sk, skb) ?
			      tp->nonagle : TCP_NAGLE_PUSH)));
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
static int tso_fragment(struct sock *sk, struct sk_buff *skb, unsigned int len,
			unsigned int mss_now)
{
	struct sk_buff *buff;
	int nlen = skb->len - len;//超出长度
	u16 flags;

	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)//如果数据块总长度包括分散数据块总长度，也包括基本数据块长度
		return tcp_fragment(sk, skb, len, mss_now);//数据包分段处理,收缩原数据包，多余数据放在新数据包中

	buff = sk_stream_alloc_skb(sk, 0, GFP_ATOMIC);//分配新的数据包和共享结构,缓冲块的长度是全部头部之和
	if (unlikely(buff == NULL))//分配失败返回
		return -ENOMEM;

	sk->sk_wmem_queued += buff->truesize;//内存计数累加分配数据包的尺寸
	sk_mem_charge(sk, buff->truesize);//递减可用内存计数器
	buff->truesize += nlen;//把超出长度累计到新数据包的实际长度中
	skb->truesize -= nlen;//原来数据包减掉超出长度

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;//初始化新数据包发送序号
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;//初始化它的结束序号
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;//调整原来数据包结束序号

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;//复制原来数据包控制标志
	TCP_SKB_CB(skb)->flags = flags & ~(TCPCB_FLAG_FIN | TCPCB_FLAG_PSH);
	TCP_SKB_CB(buff)->flags = flags;//记录控制标志

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;//清除sack

	buff->ip_summed = skb->ip_summed = CHECKSUM_PARTIAL;//设置检验和标志
	skb_split(skb, buff, len);//分隔、转嫁超出部分到新数据包

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);//设置新数据包的分段信息
	tcp_set_skb_tso_segs(sk, buff, mss_now);//设置原数据包的分段信息

	/* Link BUFF into the send queue. */
	skb_header_release(buff);//设置新数据包没有头部标志
	tcp_insert_write_queue_after(skb, buff, sk);//将新数据包链人发送队列

	return 0;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
static int tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 send_win, cong_win, limit, in_flight;

	if (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN)
		goto send_now;

	if (icsk->icsk_ca_state != TCP_CA_Open)
		goto send_now;

	/* Defer for less than two clock ticks. */
	if (tp->tso_deferred &&
	    ((jiffies << 1) >> 1) - (tp->tso_deferred >> 1) > 1)
		goto send_now;

	in_flight = tcp_packets_in_flight(tp);

	BUG_ON(tcp_skb_pcount(skb) <= 1 || (tp->snd_cwnd <= in_flight));

	send_win = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
	cong_win = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	limit = min(send_win, cong_win);

	/* If a full-sized TSO skb can be sent, do it. */
	if (limit >= sk->sk_gso_max_size)
		goto send_now;

	if (sysctl_tcp_tso_win_divisor) {
		u32 chunk = min(tp->snd_wnd, tp->snd_cwnd * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= sysctl_tcp_tso_win_divisor;
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
		if (limit > tcp_max_burst(tp) * tp->mss_cache)
			goto send_now;
	}

	/* Ok, it looks like it is advisable to defer.  */
	tp->tso_deferred = 1 | (jiffies << 1);

	return 1;

send_now:
	tp->tso_deferred = 0;
	return 0;
}

/* Create a new MTU probe if we are ready.
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
static int tcp_mtu_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);//获取tcp_sock结构体
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb, *nskb, *next;
	int len;
	int probe_size;
	int size_needed;
	int copy;
	int mss_now;

	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off) */
	if (!icsk->icsk_mtup.enabled || //没有开启mtu探测。在tcp_mtup_init()中由sysctl_tcp_mtu_probing(sysctl->net.ipv4.tcp_mtu_probing)初始化
	    icsk->icsk_mtup.probe_size || //探测probe_size 不为0。在connect流程中由tcp_mtup_init()初始化为0；在tcp_retransmit_skb()函数中也会置0，表示需要重新探测
	    inet_csk(sk)->icsk_ca_state != TCP_CA_Open || //是否发送拥塞
	    tp->snd_cwnd < 11 || //发送窗口小于11
	    tp->rx_opt.eff_sacks)//存在sack
		return -1;

	/* Very simple search strategy: just double the MSS. */
	mss_now = tcp_current_mss(sk, 0);//获取MSS大小，MSS的获取时根据MTU大小计算，MTU可以通过路由指定
	probe_size = 2 * tp->mss_cache;//探测大小
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	if (probe_size > tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_high)) {//探测大小是否超过根据MTU上限计算的MSS
		/* TODO: set timer for probe_converge_event */
		return -1;//超过就不允许发送
	}

	/* Have enough data in the send queue to probe? */
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	if (tp->snd_wnd < size_needed)
		return -1;
	if (after(tp->snd_nxt + size_needed, tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight, don't stall */
	if (tcp_packets_in_flight(tp) + 2 > tp->snd_cwnd) {
		if (!tcp_packets_in_flight(tp))
			return -1;
		else
			return 0;
	}

	/* We're allowed to probe.  Build it now. */
	if ((nskb = sk_stream_alloc_skb(sk, probe_size, GFP_ATOMIC)) == NULL)//申请skb
		return -1;
	sk->sk_wmem_queued += nskb->truesize;//记录包占用内用大小
	sk_mem_charge(sk, nskb->truesize);//检查内存是否够用

	skb = tcp_send_head(sk);//获取队列头skb

	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;//设置新数据包的起始序号
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;//设置新数据包的结束序号
	TCP_SKB_CB(nskb)->flags = TCPCB_FLAG_ACK;//设置新数据包的控制标志，发送的数据都会设置成ACK flag
	TCP_SKB_CB(nskb)->sacked = 0;//清除sack
	nskb->csum = 0;//清零校验和
	nskb->ip_summed = skb->ip_summed;//设置新数据包的校验和标志，因为从skb拷贝数据到新数据包，有可能不需要计算校验和

	tcp_insert_write_queue_before(nskb, skb, sk);//将新数据包链入插入发送队列头

	len = 0;
	//从skb开始拷贝数据到新数据包
	tcp_for_write_queue_from_safe(skb, next, sk) {//遍历发送队列
		copy = min_t(int, skb->len, probe_size - len);//从skb拷贝的字节数
		if (nskb->ip_summed)//
			skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);//拷贝数据
		else
			nskb->csum = skb_copy_and_csum_bits(skb, 0,
							    skb_put(nskb, copy),
							    copy, nskb->csum);//拷贝数据，并计算校验和

		if (skb->len <= copy) {//数据已经拷贝完
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->flags |= TCP_SKB_CB(skb)->flags;
			tcp_unlink_write_queue(skb, sk);//从发送队列删除
			sk_wmem_free_skb(sk, skb);//释放skb
		} else {//skb的数据没有拷贝完，需要调整skb包信息：包括控制标志、长度等
			TCP_SKB_CB(nskb)->flags |= TCP_SKB_CB(skb)->flags &
						   ~(TCPCB_FLAG_FIN|TCPCB_FLAG_PSH); //设置新数据包的控制标志
			if (!skb_shinfo(skb)->nr_frags) {//没有分包
				skb_pull(skb, copy);//从skb中删除拷贝数据
				if (skb->ip_summed != CHECKSUM_PARTIAL)
					skb->csum = csum_partial(skb->data,
								 skb->len, 0);//重新计算校验和
			} else {//有分包
				__pskb_trim_head(skb, copy);//更新skb的长度
				tcp_set_skb_tso_segs(sk, skb, mss_now);//更新分包信息
			}
			TCP_SKB_CB(skb)->seq += copy;//更新新数据包的起始序号
		}

		len += copy;//已经拷贝数据的长度

		if (len >= probe_size)//数据是否拷贝完成
			break;
	}
	tcp_init_tso_segs(sk, nskb, nskb->len);//计算成一个分段

	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit(). */
	TCP_SKB_CB(nskb)->when = tcp_time_stamp;//更新发送时间戳
	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {//发送数据包
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		tp->snd_cwnd--;//更新发送窗口cwnd - 1
		tcp_event_new_data_sent(sk, nskb);//为下一次发送数据做准备，并会启动本次数据定时器(超时重传)

		icsk->icsk_mtup.probe_size = tcp_mss_to_mtu(sk, nskb->len);//更新probe_size，注意此时的tcp_mss_to_mtu()中MSS是新数据包的长度
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;//记录发送MTU时开始的序号
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;//记录发送MTU时结束的序号

		return 1;
	}

	return -1;
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * Returns 1, if no segments are in flight and we have queued segments, but
 * cannot send anything now because of SWS or another problem.
 */
static int tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;

	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and all
	 * will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))//如果socket已经关闭就返回
		return 0;

	sent_pkts = 0;

	/* Do MTU probing. */
	if ((result = tcp_mtu_probe(sk)) == 0) {//检测MTU情况,如果需要等待就返回
		return 0;
	} else if (result > 0) {
		sent_pkts = 1;//设置发送计数
	}

	while ((skb = tcp_send_head(sk))) {
		unsigned int limit;
		//用MSS初始化skb中的gso字段，返回本skb将会被分割成几个TSO段传输
		tso_segs = tcp_init_tso_segs(sk, skb, mss_now);//获取分段数据包数量
		BUG_ON(!tso_segs);

		cwnd_quota = tcp_cwnd_test(tp, skb);//获取拥塞限额
		if (!cwnd_quota)//限额为0,则跳出循环
			break;

		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now)))//测试发送窗口
			break;

		if (tso_segs == 1) {//如果只有基本数据块
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))//NAGLE 测试
				break;
		} else {
			if (tcp_tso_should_defer(sk, skb))//判断是否延时发送
				break;
		}

		limit = mss_now;//记录mss 
		if (tso_segs > 1)
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    cwnd_quota);//确定发送限制长度

		if (skb->len > limit && //如果数据块总长度超过发送限制
		    unlikely(tso_fragment(sk, skb, limit, mss_now)))//数据包分段处理,收缩原数据包,多余数据放在新数据包中,将新数据包链人发送队列
			break;

		TCP_SKB_CB(skb)->when = tcp_time_stamp;//记录时间戳

		if (unlikely(tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC)))//发送套接字缓冲区中的数据包
			break;

		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		tcp_event_new_data_sent(sk, skb);//准备发送下一个数据包

		tcp_minshall_update(tp, mss_now, skb);//记录最后发送的长度
		sent_pkts++;//递增发送计数
	}

	if (likely(sent_pkts)) {//如果发送了数据包
		tcp_cwnd_validate(sk);//检测拥塞窗口
		return 0;
	}
	return !tp->packets_out && tcp_send_head(sk);//没有发送成功
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	struct sk_buff *skb = tcp_send_head(sk);//从 sock发送头获取急需发送数据包

	if (skb) {
		if (tcp_write_xmit(sk, cur_mss, nonagle))//发送数据包
			tcp_check_probe_timer(sk);//没有发送完成就重新设置发送定时器
	}
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
void tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = tcp_send_head(sk);//从 sock发送头中获取急需发送数据包
	unsigned int tso_segs, cwnd_quota;

	BUG_ON(!skb || skb->len < mss_now);

	tso_segs = tcp_init_tso_segs(sk, skb, mss_now);//初始化TSO分段数
	cwnd_quota = tcp_snd_test(sk, skb, mss_now, TCP_NAGLE_PUSH);//发送检测

	if (likely(cwnd_quota)) {//如果指定了拥塞限额
		unsigned int limit;

		BUG_ON(!tso_segs);

		limit = mss_now;//记录mss值
		if (tso_segs > 1)//需要多个分段
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    cwnd_quota);//确定发送限制长度

		if (skb->len > limit && //如果数据块长度超过发送限制，就分段新数据包
		    unlikely(tso_fragment(sk, skb, limit, mss_now)))
			return;

		/* Send it out now. */
		TCP_SKB_CB(skb)->when = tcp_time_stamp;//TCP控制结构记录时间戳

		if (likely(!tcp_transmit_skb(sk, skb, 1, sk->sk_allocation))) {//发送原数据包
			tcp_event_new_data_sent(sk, skb);//调整下一个发送的数据包
			tcp_cwnd_validate(sk);//检验拥塞窗口
			return;
		}
	}
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = icsk->icsk_ack.rcv_mss;
	int free_space = tcp_space(sk);
	int full_space = min_t(int, tp->window_clamp, tcp_full_space(sk));
	int window;

	if (mss > full_space)
		mss = full_space;

	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		if (tcp_memory_pressure)
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		if (free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = tp->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		if (((window >> tp->rx_opt.rcv_wscale) << tp->rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = (free_space / mss) * mss;
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

/* Attempt to collapse two adjacent SKB's during retransmission. */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *skb,
				     int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = tcp_write_queue_next(sk, skb);
	int skb_size, next_skb_size;
	u16 flags;

	/* The first test we must make is that neither of these two
	 * SKB's are still referenced by someone else.
	 */
	if (skb_cloned(skb) || skb_cloned(next_skb))
		return;

	skb_size = skb->len;
	next_skb_size = next_skb->len;
	flags = TCP_SKB_CB(skb)->flags;

	/* Also punt if next skb has been SACK'd. */
	if (TCP_SKB_CB(next_skb)->sacked & TCPCB_SACKED_ACKED)
		return;

	/* Next skb is out of window. */
	if (after(TCP_SKB_CB(next_skb)->end_seq, tcp_wnd_end(tp)))
		return;

	/* Punt if not enough space exists in the first SKB for
	 * the data in the second, or the total combined payload
	 * would exceed the MSS.
	 */
	if ((next_skb_size > skb_tailroom(skb)) ||
	    ((skb_size + next_skb_size) > mss_now))
		return;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	tcp_highest_sack_combine(sk, next_skb, skb);

	/* Ok.	We will be able to collapse the packet. */
	tcp_unlink_write_queue(next_skb, sk);

	skb_copy_from_linear_data(next_skb, skb_put(skb, next_skb_size),
				  next_skb_size);

	if (next_skb->ip_summed == CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_PARTIAL;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. */
	flags |= TCP_SKB_CB(next_skb)->flags; /* This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->flags = flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;
	if (TCP_SKB_CB(next_skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= tcp_skb_pcount(next_skb);
	if (TCP_SKB_CB(next_skb)->sacked & TCPCB_LOST)
		tp->lost_out -= tcp_skb_pcount(next_skb);
	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && tp->sacked_out)
		tcp_dec_pcount_approx(&tp->sacked_out, next_skb);

	tcp_adjust_fackets_out(sk, next_skb, tcp_skb_pcount(next_skb));
	tp->packets_out -= tcp_skb_pcount(next_skb);

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);

	sk_wmem_free_skb(sk, next_skb);
}

/* Do a simple retransmit without using the backoff mechanisms in
 * tcp_timer. This is used for path mtu discovery.
 * The socket is already locked here.
 */
void tcp_simple_retransmit(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int mss = tcp_current_mss(sk, 0);
	int lost = 0;

	tcp_for_write_queue(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;
		if (skb->len > mss &&
		    !(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)) {
			if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= tcp_skb_pcount(skb);
			}
			if (!(TCP_SKB_CB(skb)->sacked & TCPCB_LOST)) {
				TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
				tp->lost_out += tcp_skb_pcount(skb);
				lost = 1;
			}
		}
	}

	tcp_clear_all_retrans_hints(tp);

	if (!lost)
		return;

	if (tcp_is_reno(tp))
		tcp_limit_reno_sacked(tp);

	tcp_verify_left_out(tp);

	/* Don't muck with the congestion window here.
	 * Reason is that we do not increase amount of _data_
	 * in network, but units changed and effective
	 * cwnd/ssthresh really reduced now.
	 */
	if (icsk->icsk_ca_state != TCP_CA_Loss) {
		tp->high_seq = tp->snd_nxt;
		tp->snd_ssthresh = tcp_current_ssthresh(sk);
		tp->prior_ssthresh = 0;
		tp->undo_marker = 0;
		tcp_set_ca_state(sk, TCP_CA_Loss);
	}
	tcp_xmit_retransmit_queue(sk);
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int cur_mss;
	int err;

	/* Inconslusive MTU probe */
	if (icsk->icsk_mtup.probe_size) {
		icsk->icsk_mtup.probe_size = 0;
	}

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	if (atomic_read(&sk->sk_wmem_alloc) >
	    min(sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2), sk->sk_sndbuf))
		return -EAGAIN;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			BUG();
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = tcp_current_mss(sk, 0);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))
	    && TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	if (skb->len > cur_mss) {
		if (tcp_fragment(sk, skb, cur_mss, cur_mss))
			return -ENOMEM; /* We'll try again later. */
	}

	/* Collapse two adjacent packets if worthwhile and we can. */
	if (!(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_SYN) &&
	    (skb->len < (cur_mss >> 1)) &&
	    (tcp_write_queue_next(sk, skb) != tcp_send_head(sk)) &&
	    (!tcp_skb_is_last(sk, skb)) &&
	    (skb_shinfo(skb)->nr_frags == 0 &&
	     skb_shinfo(tcp_write_queue_next(sk, skb))->nr_frags == 0) &&
	    (tcp_skb_pcount(skb) == 1 &&
	     tcp_skb_pcount(tcp_write_queue_next(sk, skb)) == 1) &&
	    (sysctl_tcp_retrans_collapse != 0))
		tcp_retrans_try_collapse(sk, skb, cur_mss);

	/* Some Solaris stacks overoptimize and ignore the FIN on a
	 * retransmit when old data is attached.  So strip it off
	 * since it is cheap to do so and saves bytes on the network.
	 */
	if (skb->len > 0 &&
	    (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN) &&
	    tp->snd_una == (TCP_SKB_CB(skb)->end_seq - 1)) {
		if (!pskb_trim(skb, 0)) {
			/* Reuse, even though it does some unnecessary work */
			tcp_init_nondata_skb(skb, TCP_SKB_CB(skb)->end_seq - 1,
					     TCP_SKB_CB(skb)->flags);
			skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/* Make a copy, if the first transmission SKB clone we made
	 * is still in somebody's hands, else make a clone.
	 */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;

	err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);

	if (err == 0) {
		/* Update global TCP statistics. */
		TCP_INC_STATS(TCP_MIB_RETRANSSEGS);

		tp->total_retrans++;

#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
			if (net_ratelimit())
				printk(KERN_DEBUG "retrans_out leaked.\n");
		}
#endif
		if (!tp->retrans_out)
			tp->lost_retrans_low = tp->snd_nxt;
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);

		/* Save stamp of the first retransmit. */
		if (!tp->retrans_stamp)
			tp->retrans_stamp = TCP_SKB_CB(skb)->when;

		tp->undo_retrans++;

		/* snd_nxt is stored to detect loss of retransmitted segment,
		 * see tcp_input.c tcp_sacktag_write_queue().
		 */
		TCP_SKB_CB(skb)->ack_seq = tp->snd_nxt;
	}
	return err;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 * If doing SACK, the first ACK which comes back for a timeout
 * based retransmit packet might feed us FACK information again.
 * If so, we use it to avoid unnecessarily retransmissions.
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int packet_cnt;

	if (tp->retransmit_skb_hint) {
		skb = tp->retransmit_skb_hint;
		packet_cnt = tp->retransmit_cnt_hint;
	} else {
		skb = tcp_write_queue_head(sk);
		packet_cnt = 0;
	}

	/* First pass: retransmit lost packets. */
	if (tp->lost_out) {
		tcp_for_write_queue_from(skb, sk) {
			__u8 sacked = TCP_SKB_CB(skb)->sacked;

			if (skb == tcp_send_head(sk))
				break;
			/* we could do better than to assign each time */
			tp->retransmit_skb_hint = skb;
			tp->retransmit_cnt_hint = packet_cnt;

			/* Assume this retransmit will generate
			 * only one packet for congestion window
			 * calculation purposes.  This works because
			 * tcp_retransmit_skb() will chop up the
			 * packet to be MSS sized and all the
			 * packet counting works out.
			 */
			if (tcp_packets_in_flight(tp) >= tp->snd_cwnd)
				return;

			if (sacked & TCPCB_LOST) {
				if (!(sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))) {
					if (tcp_retransmit_skb(sk, skb)) {
						tp->retransmit_skb_hint = NULL;
						return;
					}
					if (icsk->icsk_ca_state != TCP_CA_Loss)
						NET_INC_STATS_BH(LINUX_MIB_TCPFASTRETRANS);
					else
						NET_INC_STATS_BH(LINUX_MIB_TCPSLOWSTARTRETRANS);

					if (skb == tcp_write_queue_head(sk))
						inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
									  inet_csk(sk)->icsk_rto,
									  TCP_RTO_MAX);
				}

				packet_cnt += tcp_skb_pcount(skb);
				if (packet_cnt >= tp->lost_out)
					break;
			}
		}
	}

	/* OK, demanded retransmission is finished. */

	/* Forward retransmissions are possible only during Recovery. */
	if (icsk->icsk_ca_state != TCP_CA_Recovery)
		return;

	/* No forward retransmissions in Reno are possible. */
	if (tcp_is_reno(tp))
		return;

	/* Yeah, we have to make difficult choice between forward transmission
	 * and retransmission... Both ways have their merits...
	 *
	 * For now we do not retransmit anything, while we have some new
	 * segments to send. In the other cases, follow rule 3 for
	 * NextSeg() specified in RFC3517.
	 */

	if (tcp_may_send_now(sk))
		return;

	/* If nothing is SACKed, highest_sack in the loop won't be valid */
	if (!tp->sacked_out)
		return;

	if (tp->forward_skb_hint)
		skb = tp->forward_skb_hint;
	else
		skb = tcp_write_queue_head(sk);

	tcp_for_write_queue_from(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;
		tp->forward_skb_hint = skb;

		if (!before(TCP_SKB_CB(skb)->seq, tcp_highest_sack_seq(tp)))
			break;

		if (tcp_packets_in_flight(tp) >= tp->snd_cwnd)
			break;

		if (TCP_SKB_CB(skb)->sacked & TCPCB_TAGBITS)
			continue;

		/* Ok, retransmit it. */
		if (tcp_retransmit_skb(sk, skb)) {
			tp->forward_skb_hint = NULL;
			break;
		}

		if (skb == tcp_write_queue_head(sk))
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
						  inet_csk(sk)->icsk_rto,
						  TCP_RTO_MAX);

		NET_INC_STATS_BH(LINUX_MIB_TCPFORWARDRETRANS);
	}
}

/* Send a fin.  The caller locks the socket for us.  This cannot be
 * allowed to fail queueing a FIN frame under any circumstances.
 */
void tcp_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_write_queue_tail(sk);
	int mss_now;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = tcp_current_mss(sk, 1);

	if (tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		/* Socket is locked, keep trying until memory is available. */
		for (;;) {
			skb = alloc_skb_fclone(MAX_TCP_HEADER, GFP_KERNEL);
			if (skb)
				break;
			yield();
		}

		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPCB_FLAG_ACK | TCPCB_FLAG_FIN);
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by RFC 2525, section 2.17.  -DaveM
 */
void tcp_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
			     TCPCB_FLAG_ACK | TCPCB_FLAG_RST);
	/* Send it off. */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	if (tcp_transmit_skb(sk, skb, 0, priority))
		NET_INC_STATS(LINUX_MIB_TCPABORTFAILED);

	TCP_INC_STATS(TCP_MIB_OUTRSTS);
}

/* WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff *skb;

	skb = tcp_write_queue_head(sk);
	if (skb == NULL || !(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_SYN)) {
		printk(KERN_DEBUG "tcp_send_synack: wrong queue state\n");
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
			if (nskb == NULL)
				return -ENOMEM;
			tcp_unlink_write_queue(skb, sk);
			skb_header_release(nskb);
			__tcp_add_write_queue_head(sk, nskb);
			sk_wmem_free_skb(sk, skb);
			sk->sk_wmem_queued += nskb->truesize;
			sk_mem_charge(sk, nskb->truesize);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_ACK;
		TCP_ECN_send_synack(tcp_sk(sk), skb);
	}
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

/*
 * Prepare a SYN-ACK.
 */
struct sk_buff *tcp_make_synack(struct sock *sk, struct dst_entry *dst,
				struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th;
	int tcp_header_size;
	struct sk_buff *skb;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *md5;
	__u8 *md5_hash_location;
#endif

	skb = sock_wmalloc(sk, MAX_TCP_HEADER + 15, 1, GFP_ATOMIC);//分配数据包结构，数据块按照16字节对齐，按照全部头部的长度进行分配
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_TCP_HEADER);

	skb->dst = dst_clone(dst);//拷贝一个缓存路由项并设置到skb->dst

	tcp_header_size = (sizeof(struct tcphdr) + TCPOLEN_MSS +
			   (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0) +
			   (ireq->wscale_ok ? TCPOLEN_WSCALE_ALIGNED : 0) +
			   /* SACK_PERM is in the place of NOP NOP of TS */
			   ((ireq->sack_ok && !ireq->tstamp_ok) ? TCPOLEN_SACKPERM_ALIGNED : 0));//计算tcp头部大小包括选项部分

#ifdef CONFIG_TCP_MD5SIG
	/* Are we doing MD5 on this segment? If so - make room for it */
	md5 = tcp_rsk(req)->af_specific->md5_lookup(sk, req);
	if (md5)
		tcp_header_size += TCPOLEN_MD5SIG_ALIGNED;
#endif
	skb_push(skb, tcp_header_size);//将data指针指向TCP头部位置
	skb_reset_transport_header(skb);//保留TCP头部位置，将sk->transport_header 指向tcp头部位置

	th = tcp_hdr(skb);//获取tcp头部指针
	memset(th, 0, sizeof(struct tcphdr));//清空tcp头部
	th->syn = 1;//设置sync标志
	th->ack = 1;//设置ack表示
	TCP_ECN_make_synack(req, th);//设置踢醒标志
	th->source = inet_sk(sk)->sport;//记录源端口
	th->dest = ireq->rmt_port;//记录目标端口
	/* Setting of flags are superfluous here for callers (and ECE is
	 * not even correctly set)
	 */
	tcp_init_nondata_skb(skb, tcp_rsk(req)->snt_isn,
			     TCPCB_FLAG_SYN | TCPCB_FLAG_ACK);
	th->seq = htonl(TCP_SKB_CB(skb)->seq);//设置序列号，在tcp_init_nondata_skb函数里面，已经将tcp_rsk(req)->snt_isn赋值给了TCP_SKB_CB(skb)->seq
	th->ack_seq = htonl(tcp_rsk(req)->rcv_isn + 1);//设置包ack号
	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns 此处rcv_wnd一定为0 */
		__u8 rcv_wscale;
		/* Set this up on the first call only */
		req->window_clamp = tp->window_clamp ? : dst_metric(dst, RTAX_WINDOW);//从路由项中获取发送窗口大小
		/* tcp_full_space because it is guaranteed to be the first packet */
		tcp_select_initial_window(tcp_full_space(sk),//FIXME:待分析
			dst_metric(dst, RTAX_ADVMSS) - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
			&req->rcv_wnd,
			&req->window_clamp,
			ireq->wscale_ok,
			&rcv_wscale);
		ireq->rcv_wscale = rcv_wscale;
	}

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rcv_wnd, 65535U));
#ifdef CONFIG_SYN_COOKIES
	if (unlikely(req->cookie_ts))
		TCP_SKB_CB(skb)->when = cookie_init_timestamp(req);
	else
#endif
	TCP_SKB_CB(skb)->when = tcp_time_stamp;//记录当前包发送时间戳，用于计算rtt
	tcp_syn_build_options((__be32 *)(th + 1), dst_metric(dst, RTAX_ADVMSS), ireq->tstamp_ok,
			      ireq->sack_ok, ireq->wscale_ok, ireq->rcv_wscale,
			      TCP_SKB_CB(skb)->when,
			      req->ts_recent,
			      (
#ifdef CONFIG_TCP_MD5SIG
			       md5 ? &md5_hash_location :
#endif
			       NULL)
			      );

	th->doff = (tcp_header_size >> 2);
	TCP_INC_STATS(TCP_MIB_OUTSEGS);

#ifdef CONFIG_TCP_MD5SIG
	/* Okay, we have all we need - do the md5 hash if needed */
	if (md5) {
		tp->af_specific->calc_md5_hash(md5_hash_location,
					       md5,
					       NULL, dst, req,
					       tcp_hdr(skb), sk->sk_protocol,
					       skb->len);
	}
#endif

	return skb;
}

/*
 * Do all connect socket setups that can be done AF independent.
 */
static void tcp_connect_init(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);//获取路由项缓存
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr) +
		(sysctl_tcp_timestamps ? TCPOLEN_TSTAMP_ALIGNED : 0);//记录头部长度；sysctl_tcp_timestamps标识是否启用timestamp时间戳

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk) != NULL)
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)//用户是否通过ioctl(TCP_MAXSEG)指定了mss
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;//记录指定的mss值。tp->rx_opt.mss_clamp在上层函数被赋值为默认的536
	tp->max_window = 0;//初始化最大窗口值
	tcp_mtup_init(sk);//初始化MTU probe 的内容
	tcp_sync_mss(sk, dst_mtu(dst));//使用路由中的mtu值，计算出mss。函数会修改mss_cache的值

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);//记录窗口值
	tp->advmss = dst_metric(dst, RTAX_ADVMSS);//记录路由指定的MSS值
	tcp_initialize_rcv_mss(sk);//初始化接收的MSS值

	tcp_select_initial_window(tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sysctl_tcp_window_scaling,
				  &rcv_wscale);//确定窗口比例和窗口值

	tp->rx_opt.rcv_wscale = rcv_wscale;//设置接收方的发送窗口比例
	tp->rcv_ssthresh = tp->rcv_wnd;//记录当前使用的窗口

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);//复位标志位
	//发送窗口大小要从输入段首部的窗口字段获取，这时还没有任何输入段，先初始化为0
	tp->snd_wnd = 0;//期望接收的窗口
	tcp_init_wl(tp, tp->write_seq, 0);//记录发送序号
	//初始化snd_una为第一个序号，该函数之后write_seq将会分配给SYN段
	tp->snd_una = tp->write_seq;//应答时的第一个字节
	tp->snd_sml = tp->write_seq;//最后一个字节
	tp->rcv_nxt = 0;//下一个要接收的
	tp->rcv_wup = 0;//窗口更新时最后一次rcv_nxt
	tp->copied_seq = 0;//未读的数据头

	inet_csk(sk)->icsk_rto = TCP_TIMEOUT_INIT;//重发时间限制
	inet_csk(sk)->icsk_retransmits = 0;//重发数目
	tcp_clear_retrans(tp);//复位重发计数器
}

/*
 * Build a SYN and send it off.
 */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;

	tcp_connect_init(sk);//初始化tcp_sock结构内容
	//为syn准备数据包
	buff = alloc_skb_fclone(MAX_TCP_HEADER + 15, sk->sk_allocation);
	if (unlikely(buff == NULL))
		return -ENOBUFS;

	/* Reserve space for headers. */
	skb_reserve(buff, MAX_TCP_HEADER);//在缓冲块中开辟TCP头部空间

	tp->snd_nxt = tp->write_seq;//记录发送序列号
	//构建SYN非数据类型的通用控制位，并自增应答序号。初始化TCBCB中的字段
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPCB_FLAG_SYN);//注意这个位置的tp->write_seq自增,说明syn占用一个发送序号
	TCP_ECN_send_syn(sk, buff);//设置ECN拥塞标志

	/* Send it off. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;//控制结构中记录发送时间，用于计算rtt
	tp->retrans_stamp = TCP_SKB_CB(buff)->when;//初始化重发时间。应该不叫重发时间，应该叫syn时间
	skb_header_release(buff);//设置没有头部nohdr标志位,表面目前还没有写入tcp头部数据
	__tcp_add_write_queue_tail(sk, buff);//将数据包放入发送队列尾部
	sk->sk_wmem_queued += buff->truesize;//调整队列长度
	sk_mem_charge(sk, buff->truesize);//调整预分配长度
	tp->packets_out += tcp_skb_pcount(buff);//调整“飞行中”的数据包计数器
	tcp_transmit_skb(sk, buff, 1, GFP_KERNEL);//发送数据包

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	tp->snd_nxt = tp->write_seq;//记录下一个发送序号
	tp->pushed_seq = tp->write_seq;//上一次push的序号
	TCP_INC_STATS(TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);//设置重发SYN的定时器
	return 0;
}

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int ato = icsk->icsk_ack.ato;
	unsigned long timeout;

	if (ato > TCP_DELACK_MIN) {
		const struct tcp_sock *tp = tcp_sk(sk);
		int max_ato = HZ / 2;

		if (icsk->icsk_ack.pingpong ||
		    (icsk->icsk_ack.pending & ICSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use inet_csk(sk)->icsk_rto here, use results of rtt measurements
		 * directly.
		 */
		if (tp->srtt) {
			int rtt = max(tp->srtt >> 3, TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		if (icsk->icsk_ack.blocked ||
		    time_before_eq(icsk->icsk_ack.timeout, jiffies + (ato >> 2))) {
			tcp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER;
	icsk->icsk_ack.timeout = timeout;
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout);
}

/* This routine sends an ack and also updates the window. */
void tcp_send_ack(struct sock *sk)
{
	struct sk_buff *buff;

	/* If we have been reset, we may not send again. */
	if (sk->sk_state == TCP_CLOSE)
		return;

	/* We are not putting this on the write queue, so
	 * tcp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	buff = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (buff == NULL) {
		inet_csk_schedule_ack(sk);
		inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
					  TCP_DELACK_MAX, TCP_RTO_MAX);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(buff, MAX_TCP_HEADER);
	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPCB_FLAG_ACK);

	/* Send it off, this clears delayed acks for us. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	tcp_transmit_skb(sk, buff, 0, GFP_ATOMIC);
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (skb == NULL)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPCB_FLAG_ACK);
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC);
}

int tcp_write_wakeup(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE)
		return -1;

	if ((skb = tcp_send_head(sk)) != NULL &&
	    before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = tcp_current_mss(sk, 0);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
			if (tcp_fragment(sk, skb, seg_size, mss))
				return -1;
		} else if (!tcp_skb_pcount(skb))
			tcp_set_skb_tso_segs(sk, skb, mss);

		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_event_new_data_sent(sk, skb);
		return err;
	} else {
		if (tp->urg_mode &&
		    between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			tcp_xmit_probe_skb(sk, 1);
		return tcp_xmit_probe_skb(sk, 0);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
void tcp_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err;

	err = tcp_write_wakeup(sk);

	if (tp->packets_out || !tcp_send_head(sk)) {
		/* Cancel probe timer, if it is not required. */
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		return;
	}

	if (err <= 0) {
		if (icsk->icsk_backoff < sysctl_tcp_retries2)
			icsk->icsk_backoff++;
		icsk->icsk_probes_out++;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
					  TCP_RTO_MAX);
	} else {
		/* If packet was not sent due to local congestion,
		 * do not backoff and do not remember icsk_probes_out.
		 * Let local senders to fight for local resources.
		 *
		 * Use accumulated backoff yet.
		 */
		if (!icsk->icsk_probes_out)
			icsk->icsk_probes_out = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff,
					      TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
	}
}

EXPORT_SYMBOL(tcp_select_initial_window);
EXPORT_SYMBOL(tcp_connect);
EXPORT_SYMBOL(tcp_make_synack);
EXPORT_SYMBOL(tcp_simple_retransmit);
EXPORT_SYMBOL(tcp_sync_mss);
EXPORT_SYMBOL(tcp_mtup_init);
