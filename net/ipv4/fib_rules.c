/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: policy rules.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * 		Thomas Graf <tgraf@suug.ch>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Fixes:
 * 		Rani Assaf	:	local_rule cannot be deleted
 *		Marc Boucher	:	routing by fwmark
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/ip_fib.h>
#include <net/fib_rules.h>
//路由规则
struct fib4_rule
{
	struct fib_rule		common;
	u8			dst_len;//目标地址长度
	u8			src_len;//源地址长度
	u8			tos;//服务类型
	__be32			src;//源地址
	__be32			srcmask;//源地址掩码
	__be32			dst;//目标地址
	__be32			dstmask;//目标地址掩码
#ifdef CONFIG_NET_CLS_ROUTE
	u32			tclassid;
#endif
};

#ifdef CONFIG_NET_CLS_ROUTE
u32 fib_rules_tclass(struct fib_result *res)
{
	return res->r ? ((struct fib4_rule *) res->r)->tclassid : 0;
}
#endif
/*支持多路由表的路由查询
flp： 路由查询条件
res：查询的结果
net->ipv4.rules_ops：当前命名空间下所有的路由规则
*/
int fib_lookup(struct net *net, struct flowi *flp, struct fib_result *res)
{
	struct fib_lookup_arg arg = {
		.result = res,
	};
	int err;
	//查找路由项。在上一篇文章初始化分析中，net->ipv4.rules_ops保存的是fib4_rules_ops_template
	err = fib_rules_lookup(net->ipv4.rules_ops, flp, 0, &arg);
	res->r = arg.rule;//保存命中的路由rule

	return err;
}

static int fib4_rule_action(struct fib_rule *rule, struct flowi *flp,
			    int flags, struct fib_lookup_arg *arg)
{
	int err = -EAGAIN;
	struct fib_table *tbl;
	//根据action值，执行相应的操作
	switch (rule->action) {
	case FR_ACT_TO_TBL:
		break;

	case FR_ACT_UNREACHABLE:
		err = -ENETUNREACH;
		goto errout;

	case FR_ACT_PROHIBIT:
		err = -EACCES;
		goto errout;

	case FR_ACT_BLACKHOLE:
	default:
		err = -EINVAL;
		goto errout;
	}
	//注意在支持多路由表的宏中找到fib_get_table函数
	if ((tbl = fib_get_table(rule->fr_net, rule->table)) == NULL)
		goto errout;
	//执行fib_table->tb_lookup()函数，开始查询具体的路由表中的路由
	err = tbl->tb_lookup(tbl, flp, (struct fib_result *) arg->result);
	if (err > 0)
		err = -EAGAIN;
errout:
	return err;
}


static int fib4_rule_match(struct fib_rule *rule, struct flowi *fl, int flags)
{
	struct fib4_rule *r = (struct fib4_rule *) rule;
	__be32 daddr = fl->fl4_dst;//目标地址
	__be32 saddr = fl->fl4_src;//源地址
	//判断源地址和目标地址是否匹配
	if (((saddr ^ r->src) & r->srcmask) ||
	    ((daddr ^ r->dst) & r->dstmask))
		return 0;
	//TOS是否匹配
	if (r->tos && (r->tos != fl->fl4_tos))
		return 0;

	return 1;
}

/*
	从0开始到RT_TABLE_MAX为止，找到第一个没有创建路由表的id后， 即调用fib_new_table创建此id对应的路由表，并返回路由表的首地址；
	若从0开始到RT_TABLE_MAX的id，都有创建相应的路由表了，则程序返回NULL
*/
static struct fib_table *fib_empty_table(struct net *net)
{
	u32 id;

	for (id = 1; id <= RT_TABLE_MAX; id++)
		if (fib_get_table(net, id) == NULL)
			return fib_new_table(net, id);
	return NULL;
}

static const struct nla_policy fib4_rule_policy[FRA_MAX+1] = {
	FRA_GENERIC_POLICY,
	[FRA_FLOW]	= { .type = NLA_U32 },
};

static int fib4_rule_configure(struct fib_rule *rule, struct sk_buff *skb,
			       struct nlmsghdr *nlh, struct fib_rule_hdr *frh,
			       struct nlattr **tb)
{
	struct net *net = sock_net(skb->sk);
	int err = -EINVAL;
	struct fib4_rule *rule4 = (struct fib4_rule *) rule;

	if (frh->tos & ~IPTOS_TOS_MASK)
		goto errout;
	//table 0表示用户没有指定路由表的id，则调用fib_empty_table创建一个路由表
	if (rule->table == RT_TABLE_UNSPEC) {
		if (rule->action == FR_ACT_TO_TBL) {
			struct fib_table *table;
			/*
			若应用层没有设置路由表的id，则调用fib_empty_table创建
			一个新的路由表，并将新创建的路由表的id传递
			给rule->table
			(使用如下命令，即会使系统创建一个新的路由表
			# ip rule add from 192.168.192.1 table 0)
			*/
			table = fib_empty_table(net);
			if (table == NULL) {
				err = -ENOBUFS;
				goto errout;
			}

			rule->table = table->tb_id;
		}
	}

	if (frh->src_len)
		rule4->src = nla_get_be32(tb[FRA_SRC]);

	if (frh->dst_len)
		rule4->dst = nla_get_be32(tb[FRA_DST]);

#ifdef CONFIG_NET_CLS_ROUTE
	if (tb[FRA_FLOW])
		rule4->tclassid = nla_get_u32(tb[FRA_FLOW]);
#endif

	rule4->src_len = frh->src_len;
	rule4->srcmask = inet_make_mask(rule4->src_len);
	rule4->dst_len = frh->dst_len;
	rule4->dstmask = inet_make_mask(rule4->dst_len);
	rule4->tos = frh->tos;

	err = 0;
errout:
	return err;
}

static int fib4_rule_compare(struct fib_rule *rule, struct fib_rule_hdr *frh,
			     struct nlattr **tb)
{
	struct fib4_rule *rule4 = (struct fib4_rule *) rule;

	if (frh->src_len && (rule4->src_len != frh->src_len))
		return 0;

	if (frh->dst_len && (rule4->dst_len != frh->dst_len))
		return 0;

	if (frh->tos && (rule4->tos != frh->tos))
		return 0;

#ifdef CONFIG_NET_CLS_ROUTE
	if (tb[FRA_FLOW] && (rule4->tclassid != nla_get_u32(tb[FRA_FLOW])))
		return 0;
#endif

	if (frh->src_len && (rule4->src != nla_get_be32(tb[FRA_SRC])))
		return 0;

	if (frh->dst_len && (rule4->dst != nla_get_be32(tb[FRA_DST])))
		return 0;

	return 1;
}

static int fib4_rule_fill(struct fib_rule *rule, struct sk_buff *skb,
			  struct nlmsghdr *nlh, struct fib_rule_hdr *frh)
{
	struct fib4_rule *rule4 = (struct fib4_rule *) rule;

	frh->family = AF_INET;
	frh->dst_len = rule4->dst_len;
	frh->src_len = rule4->src_len;
	frh->tos = rule4->tos;

	if (rule4->dst_len)
		NLA_PUT_BE32(skb, FRA_DST, rule4->dst);

	if (rule4->src_len)
		NLA_PUT_BE32(skb, FRA_SRC, rule4->src);

#ifdef CONFIG_NET_CLS_ROUTE
	if (rule4->tclassid)
		NLA_PUT_U32(skb, FRA_FLOW, rule4->tclassid);
#endif
	return 0;

nla_put_failure:
	return -ENOBUFS;
}
//rule 的优先级如果没有指定，则调用该函数进行默认配置优先级。
//返回当前可用的最大优先级。例如下面例子中，会返回32765
/*
lion@lion:~$ ip rule show
0:      from 127.0.0.1 iif lo ipproto tcp lookup 127
0:      from 127.0.0.1 iif lo ipproto udp lookup 127
0:      from all iif lo ipproto tcp lookup 128
0:      from all iif lo ipproto udp lookup 128
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
*/
static u32 fib4_rule_default_pref(struct fib_rules_ops *ops)
{
	struct list_head *pos;
	struct fib_rule *rule;

	if (!list_empty(&ops->rules_list)) {
		pos = ops->rules_list.next;
		if (pos->next != &ops->rules_list) {
			rule = list_entry(pos->next, struct fib_rule, list);
			if (rule->pref)
				return rule->pref - 1;
		}
	}

	return 0;
}

static size_t fib4_rule_nlmsg_payload(struct fib_rule *rule)
{
	return nla_total_size(4) /* dst */
	       + nla_total_size(4) /* src */
	       + nla_total_size(4); /* flow */
}

static void fib4_rule_flush_cache(void)
{
	rt_cache_flush(-1);
}

static struct fib_rules_ops fib4_rules_ops_template = {
	.family		= AF_INET,
	.rule_size	= sizeof(struct fib4_rule),
	.addr_size	= sizeof(u32),
	.action		= fib4_rule_action,
	.match		= fib4_rule_match,
	.configure	= fib4_rule_configure,//根据用户的传入参数初始化struct fib4_rule对象(继承自fib_rule对象)
	.compare	= fib4_rule_compare,//比较当前的fib rule对象与用户传入的参数是否匹配
	.fill		= fib4_rule_fill,
	.default_pref	= fib4_rule_default_pref,//取当前可用的最大优先级数值，优先级数值越低，优先级越高
	.nlmsg_payload	= fib4_rule_nlmsg_payload,
	.flush_cache	= fib4_rule_flush_cache,
	.nlgroup	= RTNLGRP_IPV4_RULE,
	.policy		= fib4_rule_policy,
	.owner		= THIS_MODULE,
};

static int fib_default_rules_init(struct fib_rules_ops *ops)
{
	int err;
	//创建本地路由规则。优先级为0，表示最高优先级，所以首先就会匹配local_rule规则，即进入local路由表中进行路由匹配，其次才会匹配其他的fib rule规则
	err = fib_default_rule_add(ops, 0, RT_TABLE_LOCAL, FIB_RULE_PERMANENT);
	if (err < 0)
		return err;
	//创建main路由。优先级0x7FFE	
	err = fib_default_rule_add(ops, 0x7FFE, RT_TABLE_MAIN, 0);
	if (err < 0)
		return err;
	//创建默认路由。优先级0x7FFF	
	err = fib_default_rule_add(ops, 0x7FFF, RT_TABLE_DEFAULT, 0);
	if (err < 0)
		return err;
	return 0;
}

int __net_init fib4_rules_init(struct net *net)
{
	int err;
	struct fib_rules_ops *ops;
	//复制模板规则函数表
	ops = kmemdup(&fib4_rules_ops_template, sizeof(*ops), GFP_KERNEL);
	if (ops == NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&ops->rules_list);
	ops->fro_net = net;
	//将ops链接到net->rules_ops链表中
	fib_rules_register(ops);//链接到网络空间结构中的专用队列

	err = fib_default_rules_init(ops);//创建3个路由规则并链接到专用队列
	if (err < 0)
		goto fail;
	net->ipv4.rules_ops = ops;//将ops保存到网络空间结构中
	return 0;

fail:
	/* also cleans all rules already added */
	fib_rules_unregister(ops);
	kfree(ops);
	return err;
}

void __net_exit fib4_rules_exit(struct net *net)
{
	fib_rules_unregister(net->ipv4.rules_ops);
	kfree(net->ipv4.rules_ops);
}
