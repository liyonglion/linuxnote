/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Version:	$Id: tcp.c,v 1.216 2002/02/01 22:01:04 davem Exp $
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
 *
 * Fixes:
 *		Alan Cox	:	Numerous verify_area() calls
 *		Alan Cox	:	Set the ACK bit on a reset
 *		Alan Cox	:	Stopped it crashing if it closed while
 *					sk->inuse=1 and was trying to connect
 *					(tcp_err()).
 *		Alan Cox	:	All icmp error handling was broken
 *					pointers passed where wrong and the
 *					socket was looked up backwards. Nobody
 *					tested any icmp error code obviously.
 *		Alan Cox	:	tcp_err() now handled properly. It
 *					wakes people on errors. poll
 *					behaves and the icmp error race
 *					has gone by moving it into sock.c
 *		Alan Cox	:	tcp_send_reset() fixed to work for
 *					everything not just packets for
 *					unknown sockets.
 *		Alan Cox	:	tcp option processing.
 *		Alan Cox	:	Reset tweaked (still not 100%) [Had
 *					syn rule wrong]
 *		Herp Rosmanith  :	More reset fixes
 *		Alan Cox	:	No longer acks invalid rst frames.
 *					Acking any kind of RST is right out.
 *		Alan Cox	:	Sets an ignore me flag on an rst
 *					receive otherwise odd bits of prattle
 *					escape still
 *		Alan Cox	:	Fixed another acking RST frame bug.
 *					Should stop LAN workplace lockups.
 *		Alan Cox	: 	Some tidyups using the new skb list
 *					facilities
 *		Alan Cox	:	sk->keepopen now seems to work
 *		Alan Cox	:	Pulls options out correctly on accepts
 *		Alan Cox	:	Fixed assorted sk->rqueue->next errors
 *		Alan Cox	:	PSH doesn't end a TCP read. Switched a
 *					bit to skb ops.
 *		Alan Cox	:	Tidied tcp_data to avoid a potential
 *					nasty.
 *		Alan Cox	:	Added some better commenting, as the
 *					tcp is hard to follow
 *		Alan Cox	:	Removed incorrect check for 20 * psh
 *	Michael O'Reilly	:	ack < copied bug fix.
 *	Johannes Stille		:	Misc tcp fixes (not all in yet).
 *		Alan Cox	:	FIN with no memory -> CRASH
 *		Alan Cox	:	Added socket option proto entries.
 *					Also added awareness of them to accept.
 *		Alan Cox	:	Added TCP options (SOL_TCP)
 *		Alan Cox	:	Switched wakeup calls to callbacks,
 *					so the kernel can layer network
 *					sockets.
 *		Alan Cox	:	Use ip_tos/ip_ttl settings.
 *		Alan Cox	:	Handle FIN (more) properly (we hope).
 *		Alan Cox	:	RST frames sent on unsynchronised
 *					state ack error.
 *		Alan Cox	:	Put in missing check for SYN bit.
 *		Alan Cox	:	Added tcp_select_window() aka NET2E
 *					window non shrink trick.
 *		Alan Cox	:	Added a couple of small NET2E timer
 *					fixes
 *		Charles Hedrick :	TCP fixes
 *		Toomas Tamm	:	TCP window fixes
 *		Alan Cox	:	Small URG fix to rlogin ^C ack fight
 *		Charles Hedrick	:	Rewrote most of it to actually work
 *		Linus		:	Rewrote tcp_read() and URG handling
 *					completely
 *		Gerhard Koerting:	Fixed some missing timer handling
 *		Matthew Dillon  :	Reworked TCP machine states as per RFC
 *		Gerhard Koerting:	PC/TCP workarounds
 *		Adam Caldwell	:	Assorted timer/timing errors
 *		Matthew Dillon	:	Fixed another RST bug
 *		Alan Cox	:	Move to kernel side addressing changes.
 *		Alan Cox	:	Beginning work on TCP fastpathing
 *					(not yet usable)
 *		Arnt Gulbrandsen:	Turbocharged tcp_check() routine.
 *		Alan Cox	:	TCP fast path debugging
 *		Alan Cox	:	Window clamping
 *		Michael Riepe	:	Bug in tcp_check()
 *		Matt Dillon	:	More TCP improvements and RST bug fixes
 *		Matt Dillon	:	Yet more small nasties remove from the
 *					TCP code (Be very nice to this man if
 *					tcp finally works 100%) 8)
 *		Alan Cox	:	BSD accept semantics.
 *		Alan Cox	:	Reset on closedown bug.
 *	Peter De Schrijver	:	ENOTCONN check missing in tcp_sendto().
 *		Michael Pall	:	Handle poll() after URG properly in
 *					all cases.
 *		Michael Pall	:	Undo the last fix in tcp_read_urg()
 *					(multi URG PUSH broke rlogin).
 *		Michael Pall	:	Fix the multi URG PUSH problem in
 *					tcp_readable(), poll() after URG
 *					works now.
 *		Michael Pall	:	recv(...,MSG_OOB) never blocks in the
 *					BSD api.
 *		Alan Cox	:	Changed the semantics of sk->socket to
 *					fix a race and a signal problem with
 *					accept() and async I/O.
 *		Alan Cox	:	Relaxed the rules on tcp_sendto().
 *		Yury Shevchuk	:	Really fixed accept() blocking problem.
 *		Craig I. Hagan  :	Allow for BSD compatible TIME_WAIT for
 *					clients/servers which listen in on
 *					fixed ports.
 *		Alan Cox	:	Cleaned the above up and shrank it to
 *					a sensible code size.
 *		Alan Cox	:	Self connect lockup fix.
 *		Alan Cox	:	No connect to multicast.
 *		Ross Biro	:	Close unaccepted children on master
 *					socket close.
 *		Alan Cox	:	Reset tracing code.
 *		Alan Cox	:	Spurious resets on shutdown.
 *		Alan Cox	:	Giant 15 minute/60 second timer error
 *		Alan Cox	:	Small whoops in polling before an
 *					accept.
 *		Alan Cox	:	Kept the state trace facility since
 *					it's handy for debugging.
 *		Alan Cox	:	More reset handler fixes.
 *		Alan Cox	:	Started rewriting the code based on
 *					the RFC's for other useful protocol
 *					references see: Comer, KA9Q NOS, and
 *					for a reference on the difference
 *					between specifications and how BSD
 *					works see the 4.4lite source.
 *		A.N.Kuznetsov	:	Don't time wait on completion of tidy
 *					close.
 *		Linus Torvalds	:	Fin/Shutdown & copied_seq changes.
 *		Linus Torvalds	:	Fixed BSD port reuse to work first syn
 *		Alan Cox	:	Reimplemented timers as per the RFC
 *					and using multiple timers for sanity.
 *		Alan Cox	:	Small bug fixes, and a lot of new
 *					comments.
 *		Alan Cox	:	Fixed dual reader crash by locking
 *					the buffers (much like datagram.c)
 *		Alan Cox	:	Fixed stuck sockets in probe. A probe
 *					now gets fed up of retrying without
 *					(even a no space) answer.
 *		Alan Cox	:	Extracted closing code better
 *		Alan Cox	:	Fixed the closing state machine to
 *					resemble the RFC.
 *		Alan Cox	:	More 'per spec' fixes.
 *		Jorge Cwik	:	Even faster checksumming.
 *		Alan Cox	:	tcp_data() doesn't ack illegal PSH
 *					only frames. At least one pc tcp stack
 *					generates them.
 *		Alan Cox	:	Cache last socket.
 *		Alan Cox	:	Per route irtt.
 *		Matt Day	:	poll()->select() match BSD precisely on error
 *		Alan Cox	:	New buffers
 *		Marc Tamsky	:	Various sk->prot->retransmits and
 *					sk->retransmits misupdating fixed.
 *					Fixed tcp_write_timeout: stuck close,
 *					and TCP syn retries gets used now.
 *		Mark Yarvis	:	In tcp_read_wakeup(), don't send an
 *					ack if state is TCP_CLOSED.
 *		Alan Cox	:	Look up device on a retransmit - routes may
 *					change. Doesn't yet cope with MSS shrink right
 *					but it's a start!
 *		Marc Tamsky	:	Closing in closing fixes.
 *		Mike Shaver	:	RFC1122 verifications.
 *		Alan Cox	:	rcv_saddr errors.
 *		Alan Cox	:	Block double connect().
 *		Alan Cox	:	Small hooks for enSKIP.
 *		Alexey Kuznetsov:	Path MTU discovery.
 *		Alan Cox	:	Support soft errors.
 *		Alan Cox	:	Fix MTU discovery pathological case
 *					when the remote claims no mtu!
 *		Marc Tamsky	:	TCP_CLOSE fix.
 *		Colin (G3TNE)	:	Send a reset on syn ack replies in
 *					window but wrong (fixes NT lpd problems)
 *		Pedro Roque	:	Better TCP window handling, delayed ack.
 *		Joerg Reuter	:	No modification of locked buffers in
 *					tcp_do_retransmit()
 *		Eric Schenk	:	Changed receiver side silly window
 *					avoidance algorithm to BSD style
 *					algorithm. This doubles throughput
 *					against machines running Solaris,
 *					and seems to result in general
 *					improvement.
 *	Stefan Magdalinski	:	adjusted tcp_readable() to fix FIONREAD
 *	Willy Konynenberg	:	Transparent proxying support.
 *	Mike McLagan		:	Routing by source
 *		Keith Owens	:	Do proper merging with partial SKB's in
 *					tcp_do_sendmsg to avoid burstiness.
 *		Eric Schenk	:	Fix fast close down bug with
 *					shutdown() followed by close().
 *		Andi Kleen 	:	Make poll agree with SIGIO
 *	Salvatore Sanfilippo	:	Support SO_LINGER with linger == 1 and
 *					lingertime == 0 (RFC 793 ABORT Call)
 *	Hirokazu Takahashi	:	Use copy_from_user() instead of
 *					csum_and_copy_from_user() if possible.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 *
 * Description of States:
 *
 *	TCP_SYN_SENT		sent a connection request, waiting for ack
 *
 *	TCP_SYN_RECV		received a connection request, sent ack,
 *				waiting for final ack in three-way handshake.
 *
 *	TCP_ESTABLISHED		connection established
 *
 *	TCP_FIN_WAIT1		our side has shutdown, waiting to complete
 *				transmission of remaining buffered data
 *
 *	TCP_FIN_WAIT2		all buffered data sent, waiting for remote
 *				to shutdown
 *
 *	TCP_CLOSING		both sides have shutdown but we still have
 *				data we have to finish sending
 *
 *	TCP_TIME_WAIT		timeout to catch resent junk before entering
 *				closed, can only be entered from FIN_WAIT2
 *				or CLOSING.  Required because the other end
 *				may not have gotten our last ACK causing it
 *				to retransmit the data packet (which we ignore)
 *
 *	TCP_CLOSE_WAIT		remote side has shutdown and is waiting for
 *				us to finish writing our data and to shutdown
 *				(we have to close() to move on to LAST_ACK)
 *
 *	TCP_LAST_ACK		out side has shutdown after remote has
 *				shutdown.  There may still be data in our
 *				buffer that we have to finish sending
 *
 *	TCP_CLOSE		socket is finished
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <linux/splice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/cache.h>
#include <linux/err.h>
#include <linux/crypto.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/netdma.h>
#include <net/sock.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

int sysctl_tcp_fin_timeout __read_mostly = TCP_FIN_TIMEOUT;

DEFINE_SNMP_STAT(struct tcp_mib, tcp_statistics) __read_mostly;

atomic_t tcp_orphan_count = ATOMIC_INIT(0);

EXPORT_SYMBOL_GPL(tcp_orphan_count);

int sysctl_tcp_mem[3] __read_mostly;//tcp所占内存限制。单位是page，此值是动态的，linux根据机器自身内存情况进行分配。在[0]这个页数之下，TCP不担心内存需求;当TCP分配的内存量超过[1]页数时，TCP将减缓其内存消耗并进入内存压力模式，当内存消耗低于[0]时，该模式将退出。所有TCP套接字允许排队的页面数。超出[2]则打印Out of socket memory
int sysctl_tcp_wmem[3] __read_mostly;//单位字节 发送缓存区大小，缓存应用程序的数据，有序列号被应答确认的数据会从发送缓冲区删除掉。[0]默认4K，为TCP套接字的发送缓冲区保留的内存量。每个TCP套接字由于其诞生的事实而有权使用它。[1]最大16K，自动调整。TCP套接字使用的发送缓冲区的初始大小。此值将覆盖net.core.wmem_default，通常低于net.core.wmem_default;[2]介于64K和4MB之间，具体取决于RAM大小。TCP套接字的发送缓冲区所允许的最大内存量。此值不会覆盖net.core.wmem_max。使用SO_SNDBUF调用setsockopt()会禁用该套接字的发送缓冲区大小的自动调整，在这种情况下该值将被忽略。
int sysctl_tcp_rmem[3] __read_mostly;//单位是字节 接收缓存区大小，缓存从对端接收的数据，后续会被应用程序读取。[0]默认值4K，TCP套接字使用的接收缓冲区的最小大小。即使在中等的内存压力下，它也能保证连接到每个TCP套接字。默认值87380字节，TCP套接字使用的接收缓冲区的初始大小。[1]此值覆盖net.core.rmem默认值。此值将导致窗口为65535;介于87380字节和6MB之间，取决RAM大小。[2]TCP套接字接收器允许接收缓冲区的最大大小，此值不会覆盖net.core.rmem_max。使用SO_RCVBUF调用setsockopt()将禁用该套接字的接收缓冲区大小的自动调整，在这种情况下，将忽略此值。

EXPORT_SYMBOL(sysctl_tcp_mem);
EXPORT_SYMBOL(sysctl_tcp_rmem);
EXPORT_SYMBOL(sysctl_tcp_wmem);

atomic_t tcp_memory_allocated;	/* Current allocated memory. */
atomic_t tcp_sockets_allocated;	/* Current number of TCP sockets. */

EXPORT_SYMBOL(tcp_memory_allocated);
EXPORT_SYMBOL(tcp_sockets_allocated);

/*
 * TCP splice context
 */
struct tcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the __sk_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int tcp_memory_pressure __read_mostly;

EXPORT_SYMBOL(tcp_memory_pressure);

void tcp_enter_memory_pressure(void)
{
	if (!tcp_memory_pressure) {
		NET_INC_STATS(LINUX_MIB_TCPMEMORYPRESSURES);
		tcp_memory_pressure = 1;
	}
}

EXPORT_SYMBOL(tcp_enter_memory_pressure);

/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	poll_wait(file, sk->sk_sleep, wait);
	if (sk->sk_state == TCP_LISTEN)
		return inet_csk_listen_poll(sk);

	/* Socket is not locked. We are protected from async events
	   by poll logic and correct handling of state changes
	   made by another threads is impossible in any case.
	 */

	mask = 0;
	if (sk->sk_err)
		mask = POLLERR;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if PULLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why PULLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if ((tp->rcv_nxt != tp->copied_seq) &&
		    (tp->urg_seq != tp->copied_seq ||
		     tp->rcv_nxt != tp->copied_seq + 1 ||
		     sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data))
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}

		if (tp->urg_data & TCP_URG_VALID)
			mask |= POLLPRI;
	}
	return mask;
}

int tcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int answ;

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !tp->urg_data ||
			 before(tp->urg_seq, tp->copied_seq) ||
			 !before(tp->urg_seq, tp->rcv_nxt)) {
			answ = tp->rcv_nxt - tp->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			if (answ && !skb_queue_empty(&sk->sk_receive_queue))
				answ -=
		       tcp_hdr((struct sk_buff *)sk->sk_receive_queue.prev)->fin;
		} else
			answ = tp->urg_seq - tp->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:
		answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_una;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return put_user(answ, (int __user *)arg);
}

static inline void tcp_mark_push(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static inline void skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);//获取tcp_sock结构指针
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);//获取TCP控制块结构

	skb->csum    = 0;//包校验和
	tcb->seq     = tcb->end_seq = tp->write_seq;//设置发送序列号
	tcb->flags   = TCPCB_FLAG_ACK;//设置标志
	tcb->sacked  = 0;//清除SACK标志
	skb_header_release(skb);//设置无头部标志
	tcp_add_write_queue_tail(sk, skb);//将数据包链入sock发送队列的尾部
	sk->sk_wmem_queued += skb->truesize;//递增内存计数
	sk_mem_charge(sk, skb->truesize);//递增可用内存计数器
	if (tp->nonagle & TCP_NAGLE_PUSH)//检查 nagle算法标志
		tp->nonagle &= ~TCP_NAGLE_PUSH;//清除标志
}

static inline void tcp_mark_urg(struct tcp_sock *tp, int flags,
				struct sk_buff *skb)
{
	if (flags & MSG_OOB) {
		tp->urg_mode = 1;
		tp->snd_up = tp->write_seq;
	}
}
//设置URG或PUSH标志后，__tcp_push_pending_frames函数来发送数据包
static inline void tcp_push(struct sock *sk, int flags, int mss_now,
			    int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_send_head(sk)) {
		struct sk_buff *skb = tcp_write_queue_tail(sk);
		if (!(flags & MSG_MORE) || forced_push(tp))
			tcp_mark_push(tp, skb);//设置PUSH标志
		tcp_mark_urg(tp, flags, skb); //设置URG标志
		__tcp_push_pending_frames(sk, mss_now,
					  (flags & MSG_MORE) ? TCP_NAGLE_CORK : nonagle);
	}
}

static int tcp_splice_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	struct tcp_splice_state *tss = rd_desc->arg.data;

	return skb_splice_bits(skb, offset, tss->pipe, tss->len, tss->flags);
}

static int __tcp_splice_read(struct sock *sk, struct tcp_splice_state *tss)
{
	/* Store TCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
	};

	return tcp_read_sock(sk, &rd_desc, tcp_splice_data_recv);
}

/**
 *  tcp_splice_read - splice data from TCP socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t tcp_splice_read(struct socket *sock, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len,
			unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct tcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & SPLICE_F_NONBLOCK);
	while (tss.len) {
		ret = __tcp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) || !timeo ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	if (spliced)
		return spliced;

	return ret;
}

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4);//分配长度4字节对齐

	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp);//分配新的数据包、缓冲块长度调整为包含头部的长度,同时分配共享结构空间,gfp是分配标志默认为 GFP KERNEL
	if (skb) {//分配成功
		if (sk_wmem_schedule(sk, skb->truesize)) {//检查数据包的实际尺寸，调整sock结构的可用内存、分配内存计数器
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb_reserve(skb, skb_tailroom(skb) - size);//调整数据块的起始、结束地址
			return skb;//返回包结构指针
		}
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure();//设置内存压力标志
		sk_stream_moderate_sndbuf(sk);//调整发送缓冲的极限值
	}
	return NULL;
}

static ssize_t do_tcp_sendpages(struct sock *sk, struct page **pages, int poffset,
			 size_t psize, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now, size_goal;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
	size_goal = tp->xmit_size_goal;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (psize > 0) {
		struct sk_buff *skb = tcp_write_queue_tail(sk);
		struct page *page = pages[poffset / PAGE_SIZE];
		int copy, i, can_coalesce;
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		if (!tcp_send_head(sk) || (copy = size_goal - skb->len) <= 0) {
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			skb = sk_stream_alloc_skb(sk, 0, sk->sk_allocation);
			if (!skb)
				goto wait_for_memory;

			skb_entail(sk, skb);
			copy = size_goal;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= MAX_SKB_FRAGS) {
			tcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		if (can_coalesce) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk_mem_charge(sk, copy);
		skb->ip_summed = CHECKSUM_PARTIAL;
		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		skb_shinfo(skb)->gso_segs = 0;

		if (!copied)
			TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

		copied += copy;
		poffset += copy;
		if (!(psize -= copy))
			goto out;

		if (skb->len < size_goal || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

		if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
			goto do_error;

		mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));
		size_goal = tp->xmit_size_goal;
	}

out:
	if (copied)
		tcp_push(sk, flags, mss_now, tp->nonagle);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	return sk_stream_error(sk, flags, err);
}

ssize_t tcp_sendpage(struct socket *sock, struct page *page, int offset,
		     size_t size, int flags)
{
	ssize_t res;
	struct sock *sk = sock->sk;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM))
		return sock_no_sendpage(sock, page, offset, size, flags);

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);
	res = do_tcp_sendpages(sk, &page, offset, size, flags);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return res;
}

#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)

static inline int select_size(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);//获取 tcp_sock 结构
	int tmp = tp->mss_cache;//获取MSS值，这个值初始化时为536，这个值在客户端与服务器握手连接过程中再次通过tcp_sync_mss()中更新
	//处理支持分散/收集（ scatter/gather）IO 的网卡。许多 卡都支持此功能，并使用 NETIF_F_SG 标志进行通告。
	//支持该特性的网卡可以处理数据 被分散到多个 buffer 的数据包;内核不需要花时间将多个缓冲区合并成一个缓冲区中。
	//避免这种额外的复制会提升性能，大多数网卡都支持此功能
	if (sk->sk_route_caps & NETIF_F_SG) {//查看路由分段标志
		//GSO就是利用NETIF_F_SG这个特性，在tcp_sendmsg的时候申请的skb的主buff只存L2/L3/L4的协议头，把所有的数据先放到skb_shinfo(skb)->frags里。
		//等到skb交给网卡驱动前再分片
		if (sk_can_gso(sk))//如果路由支持GSO特性,则直接返回0，外面只会申请主buff只存L2/L3/L4的协议头
			tmp = 0;
		else {
			int pgbreak = SKB_MAX_HEAD(MAX_TCP_HEADER);//内存页可以负载的传输层数据长度,即内存页面长度减掉全部头部的长度

			if (tmp >= pgbreak &&//检查是否超过一个内存页面的负载长度
			    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)//是否小于最大分散数据块的内存页面长度
				tmp = pgbreak;//记录内存页面的负载值为
		}
	}

	return tmp;
}

int tcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		size_t size)
{
	struct sock *sk = sock->sk;//sock 结构
	struct iovec *iov;//缓冲区结构指针
	struct tcp_sock *tp = tcp_sk(sk);//获取tcp_sock结构
	struct sk_buff *skb;//数据包指针
	int iovlen, flags;
	int mss_now, size_goal;
	int err, copied;
	long timeo;

	lock_sock(sk);//加锁,如果 sock锁被其他进程占用了,当前进程睡眠等待唤醒
	TCP_CHECK_TIMER(sk);//空语句

	flags = msg->msg_flags;//获取消息结构的标志
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);//确定发送超时时间

	/* Wait for a connection to finish. 定时等待sock进人连接状态*/
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);//清除标识

	mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));//计算mss，后面会根据这个值来分段
	size_goal = tp->xmit_size_goal;//允许发送的最大长度，基本上是tcp的mss。如果开启了TSO，则是mss的整数倍。该值在tcp_current_mss()函数中进行赋值

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;//缓冲区数量
	iov = msg->msg_iov;//缓冲区指针
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))//是否出错关闭
		goto do_error;

	while (--iovlen >= 0) {//循环发送每个缓冲区的数据
		int seglen = iov->iov_len;//缓冲区的长度
		unsigned char __user *from = iov->iov_base;//缓冲区地址

		iov++;//指向下一个缓冲区

		while (seglen > 0) {//缓冲区长度大于0，标识有效
			int copy;

			skb = tcp_write_queue_tail(sk);//获取发送队列中的最后一个包

			if (!tcp_send_head(sk) ||//如果sock发送头中没有急需发送的数据包
			    (copy = size_goal - skb->len) <= 0) {//数据包的数据块长度抵达发送极限，注意这里的skb为发送队列中的最后一个包，说明发送队列中最后一个包的数据块长度已经达到了发送极限，无法借用该包空间

new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))//如果发送缓存不足，就跳转
					goto wait_for_sndbuf;//跳转到等待缓存点
				//注意这里的size为有效负载，不包括L2/L3/L4协议头
				skb = sk_stream_alloc_skb(sk, select_size(sk),
						sk->sk_allocation);//分配数据包结构空间，按MSS大小分配。这里的select_size是根据MSS计算的
				if (!skb)//内存不足，跳转到等待内存处
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)//查看检验和能力
					skb->ip_summed = CHECKSUM_PARTIAL;//设置为硬件检验和

				skb_entail(sk, skb);//将数据包链入sock发送队列，设置seq 号、ack标识
				copy = size_goal;//复制长度为最大值
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)//如果大于缓冲区长度
				copy = seglen;//缓冲区长度做为复制长度

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {//如果数据包的主缓冲块可以存放
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))//缓冲块剩余长度是否满足复制长度
					copy = skb_tailroom(skb);//调整为缓冲块剩余长度
				if ((err = skb_add_data(skb, from, copy)) != 0)//复制用户数据(应用程序提供的数据),存放到数据包的数据块中
					goto do_fault;
			} else {//如果主缓冲块已经用完,使用分散数据块存放
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;//分散数据块数量
				struct page *page = TCP_PAGE(sk);//获取sock 结构用做发送的内存页面
				int off = TCP_OFF(sk);//获取内存页面中的偏移位置

				if (skb_can_coalesce(skb, i, page, off) &&//它是否为最后一个内存页面
				    off != PAGE_SIZE) {//如果内存页面还没有用完
					/* We can extend the last page
					 * fragment. */
					merge = 1;//设置合并标志,表示可以将数据保存到这个内存页面
				} else if (i == MAX_SKB_FRAGS ||//如果达到了分散数据块极限
					   (!i &&//如果没有分散数据块
					   !(sk->sk_route_caps & NETIF_F_SG))) {//如果不支持分散
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					tcp_mark_push(tp, skb);//设置PUSH控制标志
					goto new_segment;//分配新的数据包
				} else if (page) {//如果存在可用内存页面
					if (off == PAGE_SIZE) {//如果内存页面已经用完
						put_page(page);//递减内存页面的使用计数
						TCP_PAGE(sk) = page = NULL;//释放sock结构用做发送的内存
						off = 0;//偏移为0
					}
				} else//没有可用的内存页
					off = 0;//偏移为0

				if (copy > PAGE_SIZE - off)//如果复制长度大于内存页面剩余长度
					copy = PAGE_SIZE - off;//设置为内存页面的剩余长度

				if (!sk_wmem_schedule(sk, copy))//检查是否超过了sock分配计数
					goto wait_for_memory;//跳转到等待内存处

				if (!page) {//如果sock结构没有提供发送的内存页面
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))///分配内存页面
						goto wait_for_memory;//无法分配内存页面跳转到等待内存处
				}

				/* Time to copy data. We are close to
				 * the end! */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);//将用户数据存放到内存页面中
				if (err) {//复制出现错误
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {//sock结构没有记录发送的内存页面
						TCP_PAGE(sk) = page;//记录新建的发送内存页面
						TCP_OFF(sk) = 0;//记录内存页面偏移位置
					}
					goto do_error;//错误返回
				}

				/* Update the skb. */
				if (merge) {//如果使用了数据包最后一个分散数据块的内存页面
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;//调整分散数据块的长度
				} else {//如果使用了 sock 结构的可用内存页面或者新建的内存页面
					skb_fill_page_desc(skb, i, page, off, copy);//内存页面记录到分散数据块结构中
					if (TCP_PAGE(sk)) {//如果sock结构已经记录了这个内存页面
						get_page(page);//递增内存页面的使用计数
					} else if (off + copy < PAGE_SIZE) {//如果是新分配的内存页面并且还有剩余空间
						get_page(page);//递增内存页面的使用计数
						TCP_PAGE(sk) = page;//将内存页面记录到sock结构中
					}
				}

				TCP_OFF(sk) = off + copy;//记录内存页面目前的偏移位置
			}

			if (!copied)//如果复制完成了，清除PUSH标志
				TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

			tp->write_seq += copy;//数据长度累加到发送序号中
			TCP_SKB_CB(skb)->end_seq += copy;//数据长度累加到结束序号中
			skb_shinfo(skb)->gso_segs = 0;//设置分段数据包数量

			from += copy;//调整下一次的复制位置
			copied += copy;//累加复制长度
			if ((seglen -= copy) == 0 && iovlen == 0)//检查是否复制完成
				goto out;

			if (skb->len < size_goal || (flags & MSG_OOB))//如果数据块还没有达到极限,或者设置了带外数据标志(TCP紧急数据)
				continue;

			if (forced_push(tp)) {//检查发送序号
				tcp_mark_push(tp, skb);//设置 PUSH控制标志
				__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);//发送数据包
			} else if (skb == tcp_send_head(sk))//如果是急需发送的数据包
				tcp_push_one(sk, mss_now);//检查拥塞情况，分段发送数据包,分段后的数据包留在发送队列，下一次循环复制用户数据后发送
			continue;

wait_for_sndbuf://等待缓存点
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);//将发送队列中的数据包,调用__tcp_push_pending_frames 函数发送

			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)//定时等待超时
				goto do_error;

			mss_now = tcp_current_mss(sk, !(flags&MSG_OOB));//设置mss
			size_goal = tp->xmit_size_goal;//记录最大发送长度
		}
	}

out://如果缓冲区数据全部复制完成
	if (copied)
		tcp_push(sk, flags, mss_now, tp->nonagle);//如果是急需发送,就将队列中的最后一个数据包发送出去
	TCP_CHECK_TIMER(sk);//空语句
	release_sock(sk);//解锁,并唤醒 sock锁上的其他进程
	return copied;//返回复制的长度

do_fault://失败处理
	if (!skb->len) {//数据长度为0
		tcp_unlink_write_queue(skb, sk);//从发送队列中脱队
		/* It is the one place in all of TCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		tcp_check_send_head(sk, skb);//从发送头中摘除
		sk_wmem_free_skb(sk, skb);//释放数据包，还原内存计数
	}

do_error://错误处理
	if (copied)//如果有复制
		goto out;
out_err://超时错误
	err = sk_stream_error(sk, flags, err);//查询错误值
	TCP_CHECK_TIMER(sk);
	release_sock(sk);//解锁,并唤醒 sock锁上的其他进程
	return err;
}

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int tcp_recv_urg(struct sock *sk, long timeo,
			struct msghdr *msg, int len, int flags,
			int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {
		int err = 0;
		char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time_to_ack = 0;

#if TCP_DEBUG
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

	BUG_TRAP(!skb || before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq));
#endif

	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) {
			__u32 new_window = __tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}
	if (time_to_ack)
		tcp_send_ack(sk);
}

static void tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);//获取 tcp_sock 结构

	NET_INC_STATS_USER(LINUX_MIB_TCPPREQUEUED);//递增计数

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable();//禁用软中断
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk->sk_backlog_rcv(sk, skb);//调用tcp_v4_do_rcv()函数
	local_bh_enable();//启用软中断

	/* Clear memory counter. */
	tp->ucopy.memory = 0;//清零预处理队列内存计数
}

static inline struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		offset = seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			offset--;
		if (offset < skb->len || tcp_hdr(skb)->fin) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * This routine provides an alternative to tcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used < 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			/*
			 * If recv_actor drops the lock (e.g. TCP splice
			 * receive) the skb pointer might be invalid when
			 * getting here: tcp_collapse might have deleted it
			 * while aggregating skbs from the socket queue.
			 */
			skb = tcp_recv_skb(sk, seq-1, &offset);
			if (!skb || (offset+1 != skb->len))
				break;
		}
		if (tcp_hdr(skb)->fin) {
			sk_eat_skb(sk, skb, 0);
			++seq;
			break;
		}
		sk_eat_skb(sk, skb, 0);
		if (!desc->count)
			break;
	}
	tp->copied_seq = seq;

	tcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied > 0)
		tcp_cleanup_rbuf(sk, copied);
	return copied;
}

/*
 *	This routine copies from a sock struct into the user buffer.
 *
 *	Technical note: in 2.3 we work on _locked_ socket, so that
 *	tricks with *seq access order and skb->users are not required.
 *	Probably, code can be easily improved even more.
 */

int tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int nonblock, int flags, int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct task_struct *user_recv = NULL;//进程结构指针
	int copied_early = 0;
	struct sk_buff *skb;//数据包指针

	lock_sock(sk);//加锁,如果sock锁被其他进程占用了,当前进程睡眠等待唤醒

	TCP_CHECK_TIMER(sk);//空语句

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)//接收时应该是连接状态，如果仍于监听状态就返回
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);//确定接收的定时时间

	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)//检查紧急标志,例如控制目的的数据包
		goto recv_urg;

	seq = &tp->copied_seq;//指向接收的最后序号
	if (flags & MSG_PEEK) {//如果设置查看标志，就表示只是查看数据
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}
	//确定接收长度,MSGWAITAIL表示宁可等待也要接收到指定长度
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

#ifdef CONFIG_NET_DMA
	tp->ucopy.dma_chan = NULL;
	preempt_disable();
	skb = skb_peek_tail(&sk->sk_receive_queue);
	{
		int available = 0;

		if (skb)
			available = TCP_SKB_CB(skb)->seq + skb->len - (*seq);
		if ((available < target) &&
		    (len > sysctl_tcp_dma_copybreak) && !(flags & MSG_PEEK) &&
		    !sysctl_tcp_low_latency &&
		    __get_cpu_var(softnet_data).net_dma) {
			preempt_enable_no_resched();
			tp->ucopy.pinned_list =
					dma_pin_iovec_pages(msg->msg_iov, len);
		} else {
			preempt_enable_no_resched();
		}
	}
#endif

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {//如果是紧急数据包
			if (copied)//已经复制完成就跳出外层循环
				break;
			if (signal_pending(current)) {//如果有信号需要处理，就跳出外层循环
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;//设置返回码
				break;
			}
		}

		/* Next get a buffer. */

		skb = skb_peek(&sk->sk_receive_queue);//获取接收队列中的第一个数据包
		do {//循环获取接收队列中的每一个数据包
			if (!skb)//如果没有数据包就跳出内层循环
				break;

			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (before(*seq, TCP_SKB_CB(skb)->seq)) {//检查序号顺序,判断是否出错
				printk(KERN_INFO "recvmsg bug: copied %X "
				       "seq %X\n", *seq, TCP_SKB_CB(skb)->seq);
				break;
			}
			offset = *seq - TCP_SKB_CB(skb)->seq;//计算数据块的偏移位置
			if (tcp_hdr(skb)->syn)//如果设置了SYN标志
				offset--;//偏移位置减1,因ACK=SYN+1
			if (offset < skb->len)//如果数据块偏移位置在总长度范围，跳转
				goto found_ok_skb;
			if (tcp_hdr(skb)->fin)//如果设置了FIN标志,跳转
				goto found_fin_ok;
			BUG_TRAP(flags & MSG_PEEK);
			skb = skb->next;//处理下一个数据包
		} while (skb != (struct sk_buff *)&sk->sk_receive_queue);

		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !sk->sk_backlog.tail)//如果复制长度超过了指定接收长度或者后备队列为空就跳出外层循环
			break;

		if (copied) {//如果已经复制了数据
			if (sk->sk_err || //检查是否出错
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) || //检查socket是否停用
			    !timeo || //检查是否超时
			    signal_pending(current) || //检查是否有信号需要处理
			    (flags & MSG_PEEK))//检查是否只是查看
				break;//符合上述条件之一就跳出外层循环
		} else {//如果还没有复制数据
			if (sock_flag(sk, SOCK_DONE))//检查是否已经接收了FIN,跳出外层循环
				break;

			if (sk->sk_err) {//检查是否有错误
				copied = sock_error(sk);//返回错误
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)//如果已经关闭跳出外层循环
				break;

			if (sk->sk_state == TCP_CLOSE) {//如果socket已经停用
				if (!sock_flag(sk, SOCK_DONE)) {//如果没有接收到FIN
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;//设置错误值,跳出外层循环
					break;
				}
				break;//socket停用,跳出外层循环
			}

			if (!timeo) {//如果已经超时
				copied = -EAGAIN;//设置错误值,跳出外层循环
				break;
			}

			if (signal_pending(current)) {//如果接收到了信号,需要处理信号
				copied = sock_intr_errno(timeo);//记录超时时间,跳出外层循环
				break;
			}
		}

		tcp_cleanup_rbuf(sk, copied);//检查是否需要更新接收窗口并发送ACK
		//如果允许处理预处理队列,并且处理进程不等于接收进程
		if (!sysctl_tcp_low_latency && tp->ucopy.task == user_recv) {
			/* Install new reader */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {//如果没有指定接收进程,且不是截断和查看操作
				user_recv = current;//接收进程指定为当前进程
				tp->ucopy.task = user_recv;//记录接收进程
				tp->ucopy.iov = msg->msg_iov;//记录缓冲区(服务器程序提供)
			}

			tp->ucopy.len = len;//记录接收长度

			BUG_TRAP(tp->copied_seq == tp->rcv_nxt ||
				 (flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */
			if (!skb_queue_empty(&tp->ucopy.prequeue))//如果预处理队列不为空
				goto do_prequeue;//接收预处理队列中的数据包

			/* __ Set realtime policy in scheduler __ */
		}
		/*
		复制长度还没有达到要求,接收队列和预处理队列也没有数据包,服务器程序进程只能定时睡眠等待数据包了,这是由sk_wait data()函数设置的。
		只要接收队列有数据包到来或者定时时间已到,服务器进程就会被唤醒。
		*/
		if (copied >= target) {//复制长度达到或者超过指定长度
			/* Do not sleep, just process backlog. */
			release_sock(sk);//解锁,并唤醒sock锁上的其他进程,处理后备队列的数据包
			lock_sock(sk);//加锁,如果sock锁被其他进程占用了,当前进程睡眠等待
		} else
			sk_wait_data(sk, &timeo);//定时等待数据

#ifdef CONFIG_NET_DMA
		tp->ucopy.wakeup = 0;
#endif

		if (user_recv) {//如果指定了接收进程(服务器程序进程)
			int chunk;

			/* __ Restore normal policy in scheduler __ */

			if ((chunk = len - tp->ucopy.len) != 0) {//计算、检查可复制的长度
				NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);//增加计数
				len -= chunk;//调整下一次接收长度
				copied += chunk;//累加已复制长度
			}

			if (tp->rcv_nxt == tp->copied_seq && //检查序号
			    !skb_queue_empty(&tp->ucopy.prequeue)) {//预处理队列不为空
do_prequeue:
				tcp_prequeue_process(sk);//预处理队列的数据包处理函数

				if ((chunk = len - tp->ucopy.len) != 0) {//计算、检查可复制的长度
					NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
					len -= chunk;//调整下一次接收长度
					copied += chunk;//累加已复制长度
				}
			}
		}
		if ((flags & MSG_PEEK) && peek_seq != tp->copied_seq) { //对比查看序列号
			if (net_ratelimit())
				printk(KERN_DEBUG "TCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, task_pid_nr(current));
			peek_seq = tp->copied_seq;//记录最后接收的序号
		}
		continue;

	found_ok_skb://复制接收队列的数据包数据
		/* Ok so how much can we use? */
		used = skb->len - offset;//计算可复制长度
		if (len < used)//如果接收长度小于可复制长度
			used = len;//设置为指定长度

		/* Do we have urgent data here? */
		if (tp->urg_data) {//如果有紧急数据
			u32 urg_offset = tp->urg_seq - *seq;//计算紧急数据偏移位置
			if (urg_offset < used) {//检查紧急数据偏移位置是否在可复制范围内
				if (!urg_offset) {//如果紧急数据偏移位置为0
					if (!sock_flag(sk, SOCK_URGINLINE)) {//如果没有线性要求
						++*seq;//调整序号值
						offset++;//调整数据块偏移值
						used--;//可复制长度减少
						if (!used)//可复制长度为0,跳转到skip_copy 处
							goto skip_copy;
					}
				} else
					used = urg_offset;//确定紧急数据的复制长度
			}
		}

		if (!(flags & MSG_TRUNC)) {//如果没有设置截断数据标志
#ifdef CONFIG_NET_DMA
			if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
				tp->ucopy.dma_chan = get_softnet_dma();

			if (tp->ucopy.dma_chan) {
				tp->ucopy.dma_cookie = dma_skb_copy_datagram_iovec(
					tp->ucopy.dma_chan, skb, offset,
					msg->msg_iov, used,
					tp->ucopy.pinned_list);

				if (tp->ucopy.dma_cookie < 0) {

					printk(KERN_ALERT "dma_cookie < 0\n");

					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
				if ((offset + used) == skb->len)
					copied_early = 1;

			} else
#endif
			{
				err = skb_copy_datagram_iovec(skb, offset,
						msg->msg_iov, used);//复制数据到缓冲区(服务器程序提供)
				if (err) {//如果出错,跳出外层循环
					/* Exception. Bailout! */
					if (!copied)//设置出错值
						copied = -EFAULT;
					break;
				}
			}
		}

		*seq += used;//调整序号值
		copied += used;//记录已复制长度
		len -= used;//减少接收长度

		tcp_rcv_space_adjust(sk);//调整 TCP的接收空间值

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {//检查序列号
			tp->urg_data = 0;//清除紧急数据标志
			tcp_fast_path_check(sk);//检査乱序包队列 out_of order_queue
		}
		if (used + offset < skb->len)//如果可复制长度在数据块范围,继续外层循环
			continue;

		if (tcp_hdr(skb)->fin)//检查FIN标志
			goto found_fin_ok;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		continue;

	found_fin_ok:
		/* Process the FIN. */
		++*seq;//递增序列号
		if (!(flags & MSG_PEEK)) {//如果没有设置查看标志
			sk_eat_skb(sk, skb, copied_early);//将数据包从接收队列中脱队、释放
			copied_early = 0;
		}
		break;
	} while (len > 0);

	if (user_recv) {//如果指定了接收进程
		if (!skb_queue_empty(&tp->ucopy.prequeue)) {//预处理队列不为空
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;//设置预处理长度

			tcp_prequeue_process(sk);//预处理队列的数据包处理函数
			// 检查已复制长度和可复制长度
			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
				len -= chunk;//调整下一次接收长度
				copied += chunk;//累加已复制长度
			}
		}

		tp->ucopy.task = NULL;//清除预处理进程指针
		tp->ucopy.len = 0;//清零预处理长度
	}

#ifdef CONFIG_NET_DMA
	if (tp->ucopy.dma_chan) {
		dma_cookie_t done, used;

		dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

		while (dma_async_memcpy_complete(tp->ucopy.dma_chan,
						 tp->ucopy.dma_cookie, &done,
						 &used) == DMA_IN_PROGRESS) {
			/* do partial cleanup of sk_async_wait_queue */
			while ((skb = skb_peek(&sk->sk_async_wait_queue)) &&
			       (dma_async_is_complete(skb->dma_cookie, done,
						      used) == DMA_SUCCESS)) {
				__skb_dequeue(&sk->sk_async_wait_queue);
				kfree_skb(skb);
			}
		}

		/* Safe to free early-copied skbs now */
		__skb_queue_purge(&sk->sk_async_wait_queue);
		dma_chan_put(tp->ucopy.dma_chan);
		tp->ucopy.dma_chan = NULL;
	}
	if (tp->ucopy.pinned_list) {
		dma_unpin_iovec_pages(tp->ucopy.pinned_list);
		tp->ucopy.pinned_list = NULL;
	}
#endif

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	tcp_cleanup_rbuf(sk, copied);//检查是否需要更新接收窗口并发送ACK

	TCP_CHECK_TIMER(sk);
	release_sock(sk);//解锁,处理后备队列的数据包,并唤醒sock锁上的其他进程
	return copied; //返回复制长度,如果出错就返回出错值

out://退出
	TCP_CHECK_TIMER(sk);//空语句
	release_sock(sk);
	return err;

recv_urg://接收紧急数据
	err = tcp_recv_urg(sk, timeo, msg, len, flags, addr_len);//复制紧急数据
	goto out;
}

void tcp_set_state(struct sock *sk, int state)
{
	int oldstate = sk->sk_state;

	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED)
			TCP_INC_STATS(TCP_MIB_CURRESTAB);
		break;

	case TCP_CLOSE:
		if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
			TCP_INC_STATS(TCP_MIB_ESTABRESETS);

		sk->sk_prot->unhash(sk);
		if (inet_csk(sk)->icsk_bind_hash &&
		    !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			inet_put_port(sk);
		/* fall through */
	default:
		if (oldstate==TCP_ESTABLISHED)
			TCP_DEC_STATS(TCP_MIB_CURRESTAB);
	}

	/* Change state AFTER socket is unhashed to avoid closed
	 * socket sitting in hash tables.
	 */
	sk->sk_state = state;

#ifdef STATE_TRACE
	SOCK_DEBUG(sk, "TCP sk=%p, State %s -> %s\n",sk, statename[oldstate],statename[state]);
#endif
}
EXPORT_SYMBOL_GPL(tcp_set_state);

/*
 *	State processing on a close. This implements the state shift for
 *	sending our FIN frame. Note that we only send a FIN for some
 *	states. A shutdown() may have already sent the FIN, or we may be
 *	closed.
 */

static const unsigned char new_state[16] = {
  /* current state:        new state:      action:	*/
  /* (Invalid)		*/ TCP_CLOSE,
  /* TCP_ESTABLISHED	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_SYN_SENT	*/ TCP_CLOSE,
  /* TCP_SYN_RECV	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_FIN_WAIT1	*/ TCP_FIN_WAIT1,
  /* TCP_FIN_WAIT2	*/ TCP_FIN_WAIT2,
  /* TCP_TIME_WAIT	*/ TCP_CLOSE,
  /* TCP_CLOSE		*/ TCP_CLOSE,
  /* TCP_CLOSE_WAIT	*/ TCP_LAST_ACK  | TCP_ACTION_FIN,
  /* TCP_LAST_ACK	*/ TCP_LAST_ACK,
  /* TCP_LISTEN		*/ TCP_CLOSE,
  /* TCP_CLOSING	*/ TCP_CLOSING,
};

static int tcp_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];
	int ns = next & TCP_STATE_MASK;

	tcp_set_state(sk, ns);

	return next & TCP_ACTION_FIN;
}

/*
 *	Shutdown the sending side of a connection. Much like close except
 *	that we don't receive shut down or sock_set_flag(sk, SOCK_DEAD).
 */

void tcp_shutdown(struct sock *sk, int how)
{
	/*	We need to grab some memory, and put together a FIN,
	 *	and then put it into the queue to be sent.
	 *		Tim MacKenzie(tym@dibbler.cs.monash.edu.au) 4 Dec '92.
	 */
	if (!(how & SEND_SHUTDOWN))
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
		/* Clear out any half completed packets.  FIN if needed. */
		if (tcp_close_state(sk))
			tcp_send_fin(sk);
	}
}

void tcp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	/* As outlined in RFC 2525, section 2.17, we send a RST here because
	 * data was lost. To witness the awful effects of the old behavior of
	 * always doing a FIN, run an older 2.1.x kernel or 2.0.x, start a bulk
	 * GET in an FTP client, suspend the process, wait for the client to
	 * advertise a zero window, then kill -9 the FTP client, wheee...
	 * Note: timeout is always zero in such a case.
	 */
	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, GFP_KERNEL);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(sk)) {
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TCP_ESTABLISHED, TCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 */
		tcp_send_fin(sk);
	}

	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);
	atomic_inc(sk->sk_prot->orphan_count);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);


	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	BUG_TRAP(!sock_owned_by_user(sk));

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (sk->sk_state == TCP_FIN_WAIT2) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->linger2 < 0) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
			} else {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_too_many_orphans(sk,
				atomic_read(sk->sk_prot->orphan_count))) {
			if (net_ratelimit())
				printk(KERN_INFO "TCP: too many of orphaned "
				       "sockets\n");
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		}
	}

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/* These states need RST on ABORT according to RFC793 */

static inline int tcp_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
		TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

int tcp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err = 0;
	int old_state = sk->sk_state;

	if (old_state != TCP_CLOSE)
		tcp_set_state(sk, TCP_CLOSE);

	/* ABORT function of RFC793 */
	if (old_state == TCP_LISTEN) {
		inet_csk_listen_stop(sk);
	} else if (tcp_need_reset(old_state) ||
		   (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		/* The last check adjusts for discrepancy of Linux wrt. RFC
		 * states
		 */
		tcp_send_active_reset(sk, gfp_any());
		sk->sk_err = ECONNRESET;
	} else if (old_state == TCP_SYN_SENT)
		sk->sk_err = ECONNRESET;

	tcp_clear_xmit_timers(sk);
	__skb_queue_purge(&sk->sk_receive_queue);
	tcp_write_queue_purge(sk);
	__skb_queue_purge(&tp->out_of_order_queue);
#ifdef CONFIG_NET_DMA
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif

	inet->dport = 0;

	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	icsk->icsk_backoff = 0;
	tp->snd_cwnd = 2;
	icsk->icsk_probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = 0x7fffffff;
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	tcp_set_ca_state(sk, TCP_CA_Open);
	tcp_clear_retrans(tp);
	inet_csk_delack_init(sk);
	tcp_init_send_head(sk);
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);

	BUG_TRAP(!inet->num || icsk->icsk_bind_hash);

	sk->sk_error_report(sk);
	return err;
}

/*
 *	Socket option code for TCP.
 */
static int do_tcp_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int val;
	int err = 0;

	/* This is a string value all the others are int's */
	if (optname == TCP_CONGESTION) {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min(TCP_CA_NAME_MAX-1, optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = tcp_set_congestion_control(sk, name);
		release_sock(sk);
		return err;
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_MAXSEG:
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used */
		if (val < 8 || val > MAX_TCP_WINDOW) {
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;
		break;

	case TCP_NODELAY:
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk);
		} else {
			tp->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;

	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TCP_NAGLE_CORK;
			if (tp->nonagle&TCP_NAGLE_OFF)
				tp->nonagle |= TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk);
		}
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TCPF_CLOSE | TCPF_LISTEN))) {
				__u32 elapsed = tcp_time_stamp - tp->rcv_tstamp;
				if (tp->keepalive_time > elapsed)
					elapsed = tp->keepalive_time - elapsed;
				else
					elapsed = 0;
				inet_csk_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TCP_KEEPINTVL:
		if (val < 1 || val > MAX_TCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ;
		break;
	case TCP_KEEPCNT:
		if (val < 1 || val > MAX_TCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val;
		break;
	case TCP_SYNCNT:
		if (val < 1 || val > MAX_TCP_SYNCNT)
			err = -EINVAL;
		else
			icsk->icsk_syn_retries = val;
		break;

	case TCP_LINGER2:
		if (val < 0)
			tp->linger2 = -1;
		else if (val > sysctl_tcp_fin_timeout / HZ)
			tp->linger2 = 0;
		else
			tp->linger2 = val * HZ;
		break;

	case TCP_DEFER_ACCEPT:
		icsk->icsk_accept_queue.rskq_defer_accept = 0;
		if (val > 0) {
			/* Translate value in seconds to number of
			 * retransmits */
			while (icsk->icsk_accept_queue.rskq_defer_accept < 32 &&
			       val > ((TCP_TIMEOUT_INIT / HZ) <<
				       icsk->icsk_accept_queue.rskq_defer_accept))
				icsk->icsk_accept_queue.rskq_defer_accept++;
			icsk->icsk_accept_queue.rskq_defer_accept++;
		}
		break;

	case TCP_WINDOW_CLAMP:
		if (!val) {
			if (sk->sk_state != TCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TCP_QUICKACK:
		if (!val) {
			icsk->icsk_ack.pingpong = 1;
		} else {
			icsk->icsk_ack.pingpong = 0;
			if ((1 << sk->sk_state) &
			    (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
			    inet_csk_ack_scheduled(sk)) {
				icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
				tcp_cleanup_rbuf(sk, 1);
				if (!(val & 1))
					icsk->icsk_ack.pingpong = 1;
			}
		}
		break;

#ifdef CONFIG_TCP_MD5SIG
	case TCP_MD5SIG:
		/* Read the IP->Key mappings from userspace */
		err = tp->af_specific->md5_parse(sk, optval, optlen);
		break;
#endif

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

int tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)//不是设置tcp层选项的，调用icsk_af_ops(icsk_af_ops变量)->setsockopt()表示ip_setsockopt()函数
		return icsk->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);//设置TCP选项
}

#ifdef CONFIG_COMPAT
int compat_tcp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_setsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}

EXPORT_SYMBOL(compat_tcp_setsockopt);
#endif

/* Return information about state of tcp endpoint in API format. */
void tcp_get_info(struct sock *sk, struct tcp_info *info)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now = tcp_time_stamp;

	memset(info, 0, sizeof(*info));

	info->tcpi_state = sk->sk_state;
	info->tcpi_ca_state = icsk->icsk_ca_state;
	info->tcpi_retransmits = icsk->icsk_retransmits;
	info->tcpi_probes = icsk->icsk_probes_out;
	info->tcpi_backoff = icsk->icsk_backoff;

	if (tp->rx_opt.tstamp_ok)
		info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (tcp_is_sack(tp))
		info->tcpi_options |= TCPI_OPT_SACK;
	if (tp->rx_opt.wscale_ok) {
		info->tcpi_options |= TCPI_OPT_WSCALE;
		info->tcpi_snd_wscale = tp->rx_opt.snd_wscale;
		info->tcpi_rcv_wscale = tp->rx_opt.rcv_wscale;
	}

	if (tp->ecn_flags&TCP_ECN_OK)
		info->tcpi_options |= TCPI_OPT_ECN;

	info->tcpi_rto = jiffies_to_usecs(icsk->icsk_rto);
	info->tcpi_ato = jiffies_to_usecs(icsk->icsk_ack.ato);
	info->tcpi_snd_mss = tp->mss_cache;
	info->tcpi_rcv_mss = icsk->icsk_ack.rcv_mss;

	if (sk->sk_state == TCP_LISTEN) {
		info->tcpi_unacked = sk->sk_ack_backlog;
		info->tcpi_sacked = sk->sk_max_ack_backlog;
	} else {
		info->tcpi_unacked = tp->packets_out;
		info->tcpi_sacked = tp->sacked_out;
	}
	info->tcpi_lost = tp->lost_out;
	info->tcpi_retrans = tp->retrans_out;
	info->tcpi_fackets = tp->fackets_out;

	info->tcpi_last_data_sent = jiffies_to_msecs(now - tp->lsndtime);
	info->tcpi_last_data_recv = jiffies_to_msecs(now - icsk->icsk_ack.lrcvtime);
	info->tcpi_last_ack_recv = jiffies_to_msecs(now - tp->rcv_tstamp);

	info->tcpi_pmtu = icsk->icsk_pmtu_cookie;
	info->tcpi_rcv_ssthresh = tp->rcv_ssthresh;
	info->tcpi_rtt = jiffies_to_usecs(tp->srtt)>>3;
	info->tcpi_rttvar = jiffies_to_usecs(tp->mdev)>>2;
	info->tcpi_snd_ssthresh = tp->snd_ssthresh;
	info->tcpi_snd_cwnd = tp->snd_cwnd;
	info->tcpi_advmss = tp->advmss;
	info->tcpi_reordering = tp->reordering;

	info->tcpi_rcv_rtt = jiffies_to_usecs(tp->rcv_rtt_est.rtt)>>3;
	info->tcpi_rcv_space = tp->rcvq_space.space;

	info->tcpi_total_retrans = tp->total_retrans;
}

EXPORT_SYMBOL_GPL(tcp_get_info);

static int do_tcp_getsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_MAXSEG:
		val = tp->mss_cache;
		if (!val && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		break;
	case TCP_NODELAY:
		val = !!(tp->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(tp->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = (tp->keepalive_time ? : sysctl_tcp_keepalive_time) / HZ;
		break;
	case TCP_KEEPINTVL:
		val = (tp->keepalive_intvl ? : sysctl_tcp_keepalive_intvl) / HZ;
		break;
	case TCP_KEEPCNT:
		val = tp->keepalive_probes ? : sysctl_tcp_keepalive_probes;
		break;
	case TCP_SYNCNT:
		val = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		break;
	case TCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : sysctl_tcp_fin_timeout) / HZ;
		break;
	case TCP_DEFER_ACCEPT:
		val = !icsk->icsk_accept_queue.rskq_defer_accept ? 0 :
			((TCP_TIMEOUT_INIT / HZ) << (icsk->icsk_accept_queue.rskq_defer_accept - 1));
		break;
	case TCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TCP_INFO: {
		struct tcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		tcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUICKACK:
		val = !icsk->icsk_ack.pingpong;
		break;

	case TCP_CONGESTION:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TCP_CA_NAME_MAX);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_ca_ops->name, len))
			return -EFAULT;
		return 0;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

int tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)
		return icsk->icsk_af_ops->getsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_tcp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_getsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}

EXPORT_SYMBOL(compat_tcp_getsockopt);
#endif

struct sk_buff *tcp_tso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct tcphdr *th;
	unsigned thlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int len;

	if (!pskb_may_pull(skb, sizeof(*th)))
		goto out;

	th = tcp_hdr(skb);
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */
		int type = skb_shinfo(skb)->gso_type;
		int mss;

		if (unlikely(type &
			     ~(SKB_GSO_TCPV4 |
			       SKB_GSO_DODGY |
			       SKB_GSO_TCP_ECN |
			       SKB_GSO_TCPV6 |
			       0) ||
			     !(type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))))
			goto out;

		mss = skb_shinfo(skb)->gso_size;
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	len = skb_shinfo(skb)->gso_size;
	delta = htonl(oldlen + (thlen + len));

	skb = segs;
	th = tcp_hdr(skb);
	seq = ntohl(th->seq);

	do {
		th->fin = th->psh = 0;

		th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				       (__force u32)delta));
		if (skb->ip_summed != CHECKSUM_PARTIAL)
			th->check =
			     csum_fold(csum_partial(skb_transport_header(skb),
						    thlen, skb->csum));

		seq += len;
		skb = skb->next;
		th = tcp_hdr(skb);

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	delta = htonl(oldlen + (skb->tail - skb->transport_header) +
		      skb->data_len);
	th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				(__force u32)delta));
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		th->check = csum_fold(csum_partial(skb_transport_header(skb),
						   thlen, skb->csum));

out:
	return segs;
}
EXPORT_SYMBOL(tcp_tso_segment);

#ifdef CONFIG_TCP_MD5SIG
static unsigned long tcp_md5sig_users;
static struct tcp_md5sig_pool **tcp_md5sig_pool;
static DEFINE_SPINLOCK(tcp_md5sig_pool_lock);

static void __tcp_free_md5sig_pool(struct tcp_md5sig_pool **pool)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct tcp_md5sig_pool *p = *per_cpu_ptr(pool, cpu);
		if (p) {
			if (p->md5_desc.tfm)
				crypto_free_hash(p->md5_desc.tfm);
			kfree(p);
			p = NULL;
		}
	}
	free_percpu(pool);
}

void tcp_free_md5sig_pool(void)
{
	struct tcp_md5sig_pool **pool = NULL;

	spin_lock_bh(&tcp_md5sig_pool_lock);
	if (--tcp_md5sig_users == 0) {
		pool = tcp_md5sig_pool;
		tcp_md5sig_pool = NULL;
	}
	spin_unlock_bh(&tcp_md5sig_pool_lock);
	if (pool)
		__tcp_free_md5sig_pool(pool);
}

EXPORT_SYMBOL(tcp_free_md5sig_pool);

static struct tcp_md5sig_pool **__tcp_alloc_md5sig_pool(void)
{
	int cpu;
	struct tcp_md5sig_pool **pool;

	pool = alloc_percpu(struct tcp_md5sig_pool *);
	if (!pool)
		return NULL;

	for_each_possible_cpu(cpu) {
		struct tcp_md5sig_pool *p;
		struct crypto_hash *hash;

		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			goto out_free;
		*per_cpu_ptr(pool, cpu) = p;

		hash = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
		if (!hash || IS_ERR(hash))
			goto out_free;

		p->md5_desc.tfm = hash;
	}
	return pool;
out_free:
	__tcp_free_md5sig_pool(pool);
	return NULL;
}

struct tcp_md5sig_pool **tcp_alloc_md5sig_pool(void)
{
	struct tcp_md5sig_pool **pool;
	int alloc = 0;

retry:
	spin_lock_bh(&tcp_md5sig_pool_lock);
	pool = tcp_md5sig_pool;
	if (tcp_md5sig_users++ == 0) {
		alloc = 1;
		spin_unlock_bh(&tcp_md5sig_pool_lock);
	} else if (!pool) {
		tcp_md5sig_users--;
		spin_unlock_bh(&tcp_md5sig_pool_lock);
		cpu_relax();
		goto retry;
	} else
		spin_unlock_bh(&tcp_md5sig_pool_lock);

	if (alloc) {
		/* we cannot hold spinlock here because this may sleep. */
		struct tcp_md5sig_pool **p = __tcp_alloc_md5sig_pool();
		spin_lock_bh(&tcp_md5sig_pool_lock);
		if (!p) {
			tcp_md5sig_users--;
			spin_unlock_bh(&tcp_md5sig_pool_lock);
			return NULL;
		}
		pool = tcp_md5sig_pool;
		if (pool) {
			/* oops, it has already been assigned. */
			spin_unlock_bh(&tcp_md5sig_pool_lock);
			__tcp_free_md5sig_pool(p);
		} else {
			tcp_md5sig_pool = pool = p;
			spin_unlock_bh(&tcp_md5sig_pool_lock);
		}
	}
	return pool;
}

EXPORT_SYMBOL(tcp_alloc_md5sig_pool);

struct tcp_md5sig_pool *__tcp_get_md5sig_pool(int cpu)
{
	struct tcp_md5sig_pool **p;
	spin_lock_bh(&tcp_md5sig_pool_lock);
	p = tcp_md5sig_pool;
	if (p)
		tcp_md5sig_users++;
	spin_unlock_bh(&tcp_md5sig_pool_lock);
	return (p ? *per_cpu_ptr(p, cpu) : NULL);
}

EXPORT_SYMBOL(__tcp_get_md5sig_pool);

void __tcp_put_md5sig_pool(void)
{
	tcp_free_md5sig_pool();
}

EXPORT_SYMBOL(__tcp_put_md5sig_pool);
#endif

void tcp_done(struct sock *sk)
{
	if(sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV)
		TCP_INC_STATS_BH(TCP_MIB_ATTEMPTFAILS);

	tcp_set_state(sk, TCP_CLOSE);
	tcp_clear_xmit_timers(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);
	else
		inet_csk_destroy_sock(sk);
}
EXPORT_SYMBOL_GPL(tcp_done);

extern struct tcp_congestion_ops tcp_reno;

//static​​：限制变量作用域为当前文件。
//__initdata​​：标记该变量仅在内核初始化阶段使用，初始化完成后内存会被释放（通过链接器脚本放置在 .init.data段）。
static __initdata unsigned long thash_entries;
//​​__init​​：标记函数为初始化阶段专用，完成后内存释放。
//​​str​​：指向内核启动参数中 thash_entries=value的 value部分。
//simple_strtoul​​：将字符串转换为无符号长整型（base=0自动判断进制）。
static int __init set_thash_entries(char *str)
{
	if (!str)
		return 0;
	thash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("thash_entries=", set_thash_entries);

void __init tcp_init(void)
{
	struct sk_buff *skb = NULL;
	unsigned long nr_pages, limit;
	int order, i, max_share;

	BUILD_BUG_ON(sizeof(struct tcp_skb_cb) > sizeof(skb->cb));

	tcp_hashinfo.bind_bucket_cachep =
		kmem_cache_create("tcp_bind_bucket",
				  sizeof(struct inet_bind_bucket), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	/* Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	tcp_hashinfo.ehash =
		alloc_large_system_hash("TCP established",
					sizeof(struct inet_ehash_bucket),
					thash_entries,
					(num_physpages >= 128 * 1024) ?
					13 : 15,
					0,
					&tcp_hashinfo.ehash_size,
					NULL,
					thash_entries ? 0 : 512 * 1024);//初始化已链接的hash桶
	tcp_hashinfo.ehash_size = 1 << tcp_hashinfo.ehash_size;
	for (i = 0; i < tcp_hashinfo.ehash_size; i++) {
		INIT_HLIST_HEAD(&tcp_hashinfo.ehash[i].chain);
		INIT_HLIST_HEAD(&tcp_hashinfo.ehash[i].twchain);
	}
	if (inet_ehash_locks_alloc(&tcp_hashinfo))
		panic("TCP: failed to alloc ehash_locks");
	tcp_hashinfo.bhash =
		alloc_large_system_hash("TCP bind",
					sizeof(struct inet_bind_hashbucket),
					tcp_hashinfo.ehash_size,
					(num_physpages >= 128 * 1024) ?
					13 : 15,
					0,
					&tcp_hashinfo.bhash_size,
					NULL,
					64 * 1024);//申请管理端口哈希队列
	tcp_hashinfo.bhash_size = 1 << tcp_hashinfo.bhash_size;
	for (i = 0; i < tcp_hashinfo.bhash_size; i++) {
		spin_lock_init(&tcp_hashinfo.bhash[i].lock);
		INIT_HLIST_HEAD(&tcp_hashinfo.bhash[i].chain);
	}

	/* Try to be a bit smarter and adjust defaults depending
	 * on available memory.
	 在内存充足的系统中扩大连接管理容量，避免资源耗尽；在内存受限的系统中收缩限制，防止内存溢出。
	 */
	//计算存储 bhash哈希表所需的内存页数量（order表示连续内存块的阶数）。
	//(1 << order) << PAGE_SHIFT：计算 2^order页的内存总大小（字节）。
	//找到最小的 order，使得内存页足够容纳 bhash。
	for (order = 0; ((1 << order) << PAGE_SHIFT) <
			(tcp_hashinfo.bhash_size * sizeof(struct inet_bind_hashbucket));//tcp_hashinfo.bhash_size * sizeof(struct inet_bind_hashbucket)：bhash哈希表的总大小。
			order++)
		;
	/*
	​​sysctl_max_tw_buckets​​：最大 TIME_WAIT 套接字数量。
	sysctl_tcp_max_orphans​​：最大孤儿套接字（无用户引用的套接字）数量。
	​​sysctl_max_syn_backlog​​：SYN 半连接队列的最大长度。
	*/
	if (order >= 4) {//内存充足时，扩展TCP连接管理容量。
		tcp_death_row.sysctl_max_tw_buckets = 180000;// 增大 TIME_WAIT 容量
		sysctl_tcp_max_orphans = 4096 << (order - 4);// 孤儿套接字数量随内存扩展
		sysctl_max_syn_backlog = 1024; // 增大 SYN 队列
	} else if (order < 3) {//内存受限
		tcp_death_row.sysctl_max_tw_buckets >>= (3 - order);
		sysctl_tcp_max_orphans >>= (3 - order);
		sysctl_max_syn_backlog = 128;
	}

	/* Set the pressure threshold to be a fraction of global memory that
	 * is up to 1/2 at 256 MB, decreasing toward zero with the amount of
	 * memory, with a floor of 128 pages.
	 */
	nr_pages = totalram_pages - totalhigh_pages;
	limit = min(nr_pages, 1UL<<(28-PAGE_SHIFT)) >> (20-PAGE_SHIFT);
	limit = (limit * (nr_pages >> (20-PAGE_SHIFT))) >> (PAGE_SHIFT-11);
	limit = max(limit, 128UL);
	sysctl_tcp_mem[0] = limit / 4 * 3;//TCP内存压力阈值。在次内存之下，TCP子系统不担心它的内存需求。
	sysctl_tcp_mem[1] = limit;//当TCP分配的内存量超过此页数时，TCP将减缓其内存消耗并进入内存压力模式，当内存消耗低于[0]时，该模式将退出。
	sysctl_tcp_mem[2] = sysctl_tcp_mem[0] * 2;//所有TCP套接字允许排队的页面数。超出则打印Out of socket memory

	/* Set per-socket limits to no more than 1/128 the pressure threshold */
	limit = ((unsigned long)sysctl_tcp_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL*1024*1024, limit);

	sysctl_tcp_wmem[0] = SK_MEM_QUANTUM;//默认4K,单位字节。为TCP套接字的发送缓冲区保留的内存量。每个TCP套接字由于其诞生的事实而有权使用它。
	sysctl_tcp_wmem[1] = 16*1024;//16K，自动调整。TCP套接字使用的发送缓冲区的初始大小。此值将覆盖net.core.wmem_default，通常低于net.core.wmem_default。
	sysctl_tcp_wmem[2] = max(64*1024, max_share);//介于64K和4MB之间，具体取决于RAM大小。TCP套接字的发送缓冲区所允许的最大内存量。此值不会覆盖net.core.wmem_max。使用SO_SNDBUF调用setsockopt()会禁用该套接字的发送缓冲区大小的自动调整，在这种情况下该值将被忽略。

	sysctl_tcp_rmem[0] = SK_MEM_QUANTUM; //默认值4K，单位字节。TCP套接字使用的接收缓冲区的最小大小。即使在中等的内存压力下，它也能保证连接到每个TCP套接字。
	sysctl_tcp_rmem[1] = 87380;//默认值87380字节，TCP套接字使用的接收缓冲区的初始大小。此值覆盖net.core.rmem默认值。此值将导致窗口为65535，默认设置为tcp_adv_win_scale和tcp_app_win:0，默认设置为tcp_app_win时，窗口会小一些。
	sysctl_tcp_rmem[2] = max(87380, max_share);//介于87380字节和6MB之间，取决RAM大小。TCP套接字接收器允许接收缓冲区的最大大小，此值不会覆盖net.core.rmem_max。使用SO_RCVBUF调用setsockopt()将禁用该套接字的接收缓冲区大小的自动调整，在这种情况下，将忽略此值。

	printk(KERN_INFO "TCP: Hash tables configured "
	       "(established %d bind %d)\n",
	       tcp_hashinfo.ehash_size, tcp_hashinfo.bhash_size);
	//注册拥塞控制算法
	tcp_register_congestion_control(&tcp_reno);
}

EXPORT_SYMBOL(tcp_close);
EXPORT_SYMBOL(tcp_disconnect);
EXPORT_SYMBOL(tcp_getsockopt);
EXPORT_SYMBOL(tcp_ioctl);
EXPORT_SYMBOL(tcp_poll);
EXPORT_SYMBOL(tcp_read_sock);
EXPORT_SYMBOL(tcp_recvmsg);
EXPORT_SYMBOL(tcp_sendmsg);
EXPORT_SYMBOL(tcp_splice_read);
EXPORT_SYMBOL(tcp_sendpage);
EXPORT_SYMBOL(tcp_setsockopt);
EXPORT_SYMBOL(tcp_shutdown);
EXPORT_SYMBOL(tcp_statistics);
