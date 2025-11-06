/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source;//16位源端口号
	__be16	dest;//16位目的端口号
	__be32	seq;//此次发送的数据在整个报文段中的起始字节数。此序号用来标识从tcp发送端向tcp接受端发送的数据字节流，seq表示在这个报文段中的第一个数据字节。如果将字节流看做在两个应用程序间的单向流动，则tcp用序号对每个字节进行计数。32 bit的无符号数。为了安全起见，它的初始值是一个随机生成的数，它到达2的32次方-1后又从零开始。
	__be32	ack_seq; //是下一个期望接收的字节，确认序号应当是上次已成功接收的序号+1，只有ack标志为1时确认序号字段才有效。一旦一个连接已经建立了，ack总是=1
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4, // 保留位
		doff:4,  //tcp头部长度，指明了在tcp头部中包含了多少个32位的字。由于options域的长度是可变的，所以整个tcp头部的长度也是变化的。4bit可表示最大值15，故15*32=480bit=60字节，所以tcp首部最长60字节。然后，没有任选字段，正常的长度是20字节
		fin:1, //发端完成发送任务
		syn:1,//同步序号用来发起一个连接
		rst:1, //重建连接
		psh:1, //接收方应该尽快将这个报文段交给应用层
		ack:1,//一旦一个连接已经建立了，ack总是=1
		urg:1, //紧急指针有效
		ece:1, //拥塞控制
		cwr:1; //拥塞控制
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window; //窗口大小，单位字节数，指接收端正期望接受的字节，16bit，故窗口大小最大为16bit=1111 1111 1111 1111（二进制）=65535（十进制）字节
	__sum16	check;//校验和校验的是整个tcp报文段，包括tcp首部和tcp数据，这是一个强制性的字段，一定是由发端计算和存储，并由收端进行验证。
	__be16	urg_ptr; //紧急指针
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl 用户设置的本端 MSS。用户可以通过 TCP_MAXSEG 这个 socket 选项对这个字段进行设置，这个字段在 rx_opt 中，说明用户设置该字段起到的作用就如同收到了对端通告的 MSS 值。 */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup 连接建立阶段本端计算出的 MSS。它取user_mss和 对端 SYN(SYNACK) 报文通告的 MSS 值中的较小值，如果用户没有设置 user_mss，则就为对端报文中的 MSS 值。我们可以理解为生效 MSS的最大值。*/
};

struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	//客户端syn段中携带的seq，即客户端的初始序列号
	u32			 	rcv_isn;
	//SYN+ACK段携带的seq，即服务端的初始化序列号
	u32			 	snt_isn;//发送端seq序列号
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}
//tcp_sock(TCP专用，例如拥塞管理、序列号等等)-->inet_connection_sock(连接层)--->inet_sock(IPV4/IPV6基础层，如端口号、IP地址)--->sock(所有协议族公用)继承关系
//存储 ​​TCP 协议独有的状态和数据​​，如序列号、拥塞控制、滑动窗口等。是内核中 TCP 套接字的核心数据结构，所有 TCP 专属操作均依赖此结构。
struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	tcp_header_len;	/* Bytes of tcp header to send	发送的 tcp 头部字节数，包括tcp选项头(不包括sack大小)大小	*/
	u16	xmit_size_goal;	/* Goal for segmenting output packets 分段传送的数据包大小	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 头部的预置位
0x5? 10 << 16 + snd wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 根据 REC793标准定义的变量。可以参考 REC793 和 REC1122了解这些内容
 */
/*
                 
				 |<-------------发送窗口(tp->snd_wnd)---->|
  已发送已确认    |   已发送未确认  |  未发送且在发送窗口内  |  未发送且未在发送窗口内  
                 ⬆                ⬆               
				 tp->snd_una 	  tp->snd_nxt
				 
*/
 	u32	rcv_nxt;	/* What we want to receive next 下一个要接收的目标	*/
	u32	copied_seq;	/* Head of yet unread data	代表还没有读取的数据	*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent rcv_nxt 在最后一次窗口更新时内容	*/
 	u32	snd_nxt;	/* Next sequence we send	下一个要发送的序号，即序号等于snd_nxt的数据还没有发送	*/

 	u32	snd_una;	//已经发送，但是还没有被确认的最小序号，注意序号等于snd_una的数据已经发送，最想收到的确认号要大于snd_una。但是有一个特殊情况，如果发送的所有数据都已经被确认，那么snd_una将等于下一个要发送的数据，即snd_una代表的数据还没有发送
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet 最近发送数据包中的尾字节 */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) 最后一次接收到 ACK 的时间 */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) 最后一次发送数据包的时间 */

	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue; //预处理队列
		struct task_struct	*task; //预处理进程：用户进程
		struct iovec		*iov; //用户程序(应用程序)接收数据的缓冲区
		int			memory; //预处理数据包计数器
		int			len; //预处理长度
#ifdef CONFIG_NET_DMA
		/* members for async copy 异步复制的内容*/
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	u32	snd_wl1;	/* Sequence for window update	窗口更新的顺序	*/
	u32	snd_wnd;	/* 发送窗口大小，以字节为单位，来源于输入段首部的窗口字段，即对端接收缓冲区的剩余大小。对snd_wnd的初始化发生在收到SYN+ACK段	*/
	u32	max_window;	/* 记录到目前为止对端通告过的窗口的最大值，可以代表对端接收缓冲区的最大值	*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS 生效 MSS。它是这几个字段中最重要的，表示本端 TCP 发包实际的分段大小依据，它的值在连接过程中可能发生变化。无论是主动端还是被动端，在创建tcp_sock时，就会对mss_cache进行初始化为 TCP_MSS_DEFAULT(536)，在tcp_init_sock()中初始化*/

	u32	window_clamp;	/* Maximal window to advertise 对外公布的最大窗口		*/
	u32	rcv_ssthresh;	/* Current window clamp		当前窗口	*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred 在RTO时的snd_nxt */
	u8	reordering;	/* Packet reordering metric.	包最大重排序数量	*/
	u8	frto_counter;	/* Number of new acks after RTO  RTO 后的 ack 次数*/
	u8	nonagle;	/* Disable Nagle algorithm?    是否使用Nagle算法         */
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
	u32	srtt;		/* smoothed round trip time << 3	*/
	u32	mdev;		/* medium deviation			*/
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	u32	rttvar;		/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	u32	packets_out;	/* Packets which are "in flight" 发出去数据包总大小。用于计算飞行中的数据包总大小*/
	u32	retrans_out;	/* Retransmitted packets out	转发的数据包数量	*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 		接收选项
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold	慢起动的起点值	*/
 	u32	snd_cwnd;	/* Sending congestion window	发送的阻塞窗口，单位mss	*/
	u32	snd_cwnd_cnt;	/* Linear increase counter	线性计数器	*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this 不允许 snd_cwnd 超过的值 */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here 超出分段规则的队列 */

 	u32	rcv_wnd;	/* Current receiver window	当前接收窗口	*/
	u32	write_seq;	/* 写系统调用一旦成功返回，说明数据一被TCP协议接收，这时就要为每一个数据分配一个序号，write_seq就是下一个要分配的序号，其初始值由secure_tcp_sequence_number()基于算法生成。注意等于write_seq的序号还没有被分配 */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows  最后送出的push顺序号，需要通知窗口*/

/*	SACKs data	*/
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* highest skb with SACK received
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;

	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	struct sk_buff *forward_skb_hint;

	int     lost_cnt_hint;
	int     retransmit_cnt_hint;

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

	u16	advmss;		/* Advertised MSS	本端向对端通告的包含option的 MSS 值。举个例子，当网卡 MTU 为 1500 字节时，通信双方通告的 MSS 都应该为 1460 字节，但如果双方都开启了 TCP timestamp 选项(会占用 12 字节)，则advmss的值会是 1448		*/
	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. 记录发送SYN的时间戳，对于超时重传syn，也需要更新该值。就是记录发送syn的时间戳*/
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	urg_seq;	/* Seq of received urgent pointer */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	urg_mode;	/* In urgent mode		*/
	u8	ecn_flags;	/* ECN status bits.	ecn控制位		*/
	u32	snd_up;		/* Urgent pointer		*/

	u32	total_retrans;	/* Total retransmits for entire connection */
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */
	//keepalive相关
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	int			linger2;

	unsigned long last_synq_overflow; 

	u32	tso_deferred;

/* Receiver side RTT estimation 计算RTT相关*/
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space 接收队列空间 */
	struct {
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. TCP 指定的MTU检验内容*/
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {//对tcp套接字处于TCP_TIME_WAIT状态的描述；处于timewait状态时，tcp_sock结构体会变成tcp_timewait_sock结构体。
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
