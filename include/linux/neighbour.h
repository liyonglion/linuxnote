#ifndef __LINUX_NEIGHBOUR_H
#define __LINUX_NEIGHBOUR_H

#include <linux/netlink.h>

struct ndmsg
{
	__u8		ndm_family;
	__u8		ndm_pad1;
	__u16		ndm_pad2;
	__s32		ndm_ifindex;
	__u16		ndm_state;
	__u8		ndm_flags;
	__u8		ndm_type;
};

enum
{
	NDA_UNSPEC,
	NDA_DST,
	NDA_LLADDR,
	NDA_CACHEINFO,
	NDA_PROBES,
	__NDA_MAX
};

#define NDA_MAX (__NDA_MAX - 1)

/*
 *	Neighbor Cache Entry Flags
 */

#define NTF_PROXY	0x08	/* == ATF_PUBL */
#define NTF_ROUTER	0x80

/*
 *	Neighbor Cache Entry States.
 */
/*
对于NUD_INCOMPLETE，当本机发送完arp 请求包后，还未收到应答时，即会进入该状态，进入该状态，即会启动定时器，如果在定时器到期后，
还没有收到应答时:如果没有到达最大发包上限时，即会重新进行发送请求报文，如果超过最大发包上限还没有收到应答，则会将状态设置为failed
*/
#define NUD_INCOMPLETE	0x01//未完成状态，表示正在解析地址，但邻居链路层地址尚未确定
/*
对于收到可到达性确认后，即会进入NUD_REACHABLE,当进入NUD_REACHABLE状态。当进入NUD_REACHABLE后，即会启动个定时器，当定时器到时前，该邻居协议没有
被使用过，就会将邻居项的状态转换为NUD_STALE
*/
#define NUD_REACHABLE	0x02//可达状态，表示地址解析成功，该邻居可达
/*
对于进入NUD_STALE状态的邻居项，即会启动一个定时器，如果在定时器到时前，有数据需要发送，则直接将数据包发送出去，并将状态设置为NUD_DELAY;
如果在定时器到时，没有数据需要发送，且该邻居项的引用计数为1，则会通过垃圾回收机制，释放该邻居项对应的缓存
*/
#define NUD_STALE	0x04//失效状态: 表示可达时间耗尽，未确定邻居是否可达
/*
处于NUD_DELAY状态的邻居项，如果在定时器到时后，没有收到可到达性确认，则会进入NUD_PROBE状态，如果在定时器到达之前，收到可到达性确认，
则会进入NUD REACHABLE (在该状态下的邻居项不会发送solicit请求，而只是等待可到达性应答。主要包括对以前的solicit请求的应答或者收到一个对于本设备以前发送的一个数据包的应答)
*/
#define NUD_DELAY	0x08//延迟状态，表示未确定邻居是否可达。DELAY状态不是一个稳定的状态，而是一个延时等待状态
/*
处于NUD_PROBE状态的邻居项，会发送arp solicit请求，并启动一个定时器。如果在定时器到时前，收到可到达性确认，则进入NUD_REACHABLE; 如果在定时器到时后，没有收到可到达性确认:
	a)没有超过最大发包次数时，则继续发送solicit请求，并启动定时器
	b)如果超过最大发包次数，则将邻居项状态设置为failed
*/
#define NUD_PROBE	0x10//探测状态: 节点会向处FPROBE状态的领居号续发送VS报X
#define NUD_FAILED	0x20//失败垃圾回收

/* Dummy states */
//以下状态 无需邻居探测
#define NUD_NOARP	0x40
#define NUD_PERMANENT	0x80
#define NUD_NONE	0x00

/* NUD_NOARP & NUD_PERMANENT are pseudostates, they never change
   and make no address resolution or NUD.
   NUD_PERMANENT is also cannot be deleted by garbage collectors.
 */

struct nda_cacheinfo
{
	__u32		ndm_confirmed;
	__u32		ndm_used;
	__u32		ndm_updated;
	__u32		ndm_refcnt;
};

/*****************************************************************
 *		Neighbour tables specific messages.
 *
 * To retrieve the neighbour tables send RTM_GETNEIGHTBL with the
 * NLM_F_DUMP flag set. Every neighbour table configuration is
 * spread over multiple messages to avoid running into message
 * size limits on systems with many interfaces. The first message
 * in the sequence transports all not device specific data such as
 * statistics, configuration, and the default parameter set.
 * This message is followed by 0..n messages carrying device
 * specific parameter sets.
 * Although the ordering should be sufficient, NDTA_NAME can be
 * used to identify sequences. The initial message can be identified
 * by checking for NDTA_CONFIG. The device specific messages do
 * not contain this TLV but have NDTPA_IFINDEX set to the
 * corresponding interface index.
 *
 * To change neighbour table attributes, send RTM_SETNEIGHTBL
 * with NDTA_NAME set. Changeable attribute include NDTA_THRESH[1-3],
 * NDTA_GC_INTERVAL, and all TLVs in NDTA_PARMS unless marked
 * otherwise. Device specific parameter sets can be changed by
 * setting NDTPA_IFINDEX to the interface index of the corresponding
 * device.
 ****/

struct ndt_stats
{
	__u64		ndts_allocs;
	__u64		ndts_destroys;
	__u64		ndts_hash_grows;
	__u64		ndts_res_failed;
	__u64		ndts_lookups;
	__u64		ndts_hits;
	__u64		ndts_rcv_probes_mcast;
	__u64		ndts_rcv_probes_ucast;
	__u64		ndts_periodic_gc_runs;
	__u64		ndts_forced_gc_runs;
};

enum {
	NDTPA_UNSPEC,
	NDTPA_IFINDEX,			/* u32, unchangeable */
	NDTPA_REFCNT,			/* u32, read-only */
	NDTPA_REACHABLE_TIME,		/* u64, read-only, msecs */
	NDTPA_BASE_REACHABLE_TIME,	/* u64, msecs */
	NDTPA_RETRANS_TIME,		/* u64, msecs */
	NDTPA_GC_STALETIME,		/* u64, msecs */
	NDTPA_DELAY_PROBE_TIME,		/* u64, msecs */
	NDTPA_QUEUE_LEN,		/* u32 */
	NDTPA_APP_PROBES,		/* u32 */
	NDTPA_UCAST_PROBES,		/* u32 */
	NDTPA_MCAST_PROBES,		/* u32 */
	NDTPA_ANYCAST_DELAY,		/* u64, msecs */
	NDTPA_PROXY_DELAY,		/* u64, msecs */
	NDTPA_PROXY_QLEN,		/* u32 */
	NDTPA_LOCKTIME,			/* u64, msecs */
	__NDTPA_MAX
};
#define NDTPA_MAX (__NDTPA_MAX - 1)

struct ndtmsg
{
	__u8		ndtm_family;
	__u8		ndtm_pad1;
	__u16		ndtm_pad2;
};

struct ndt_config
{
	__u16		ndtc_key_len;
	__u16		ndtc_entry_size;
	__u32		ndtc_entries;
	__u32		ndtc_last_flush;	/* delta to now in msecs */
	__u32		ndtc_last_rand;		/* delta to now in msecs */
	__u32		ndtc_hash_rnd;
	__u32		ndtc_hash_mask;
	__u32		ndtc_hash_chain_gc;
	__u32		ndtc_proxy_qlen;
};

enum {
	NDTA_UNSPEC,
	NDTA_NAME,			/* char *, unchangeable */
	NDTA_THRESH1,			/* u32 */
	NDTA_THRESH2,			/* u32 */
	NDTA_THRESH3,			/* u32 */
	NDTA_CONFIG,			/* struct ndt_config, read-only */
	NDTA_PARMS,			/* nested TLV NDTPA_* */
	NDTA_STATS,			/* struct ndt_stats, read-only */
	NDTA_GC_INTERVAL,		/* u64, msecs */
	__NDTA_MAX
};
#define NDTA_MAX (__NDTA_MAX - 1)

#endif
