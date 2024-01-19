#ifndef __NET_NEXTHOP_H
#define __NET_NEXTHOP_H

#include <linux/rtnetlink.h>
#include <net/netlink.h>

static inline int rtnh_ok(const struct rtnexthop *rtnh, int remaining)
{
	return remaining >= sizeof(*rtnh) &&
	       rtnh->rtnh_len >= sizeof(*rtnh) &&
	       rtnh->rtnh_len <= remaining;
}

static inline struct rtnexthop *rtnh_next(const struct rtnexthop *rtnh,
                                         int *remaining)
{
	int totlen = NLA_ALIGN(rtnh->rtnh_len);//取得rtnext结构的长度

	*remaining -= totlen;//减少长度
	return (struct rtnexthop *) ((char *) rtnh + totlen);//指向下一个rtnexthop结构
}

static inline struct nlattr *rtnh_attrs(const struct rtnexthop *rtnh)
{
	return (struct nlattr *) ((char *) rtnh + NLA_ALIGN(sizeof(*rtnh)));
}

static inline int rtnh_attrlen(const struct rtnexthop *rtnh)
{
	return rtnh->rtnh_len - NLA_ALIGN(sizeof(*rtnh));
}

#endif
