/*
 * net/core/fib_rules.c		Generic Routing Rules
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/fib_rules.h>

int fib_default_rule_add(struct fib_rules_ops *ops,
			 u32 pref, u32 table, u32 flags)
{
	struct fib_rule *r;

	r = kzalloc(ops->rule_size, GFP_KERNEL);
	if (r == NULL)
		return -ENOMEM;

	atomic_set(&r->refcnt, 1);
	r->action = FR_ACT_TO_TBL;
	r->pref = pref;
	r->table = table;
	r->flags = flags;
	r->fr_net = hold_net(ops->fro_net);

	/* The lock is not required here, the list in unreacheable
	 * at the moment this function is called */
	list_add_tail(&r->list, &ops->rules_list);//加入到当前的命名空间net->ipv4.rules_ops.rulus_list
	return 0;
}
EXPORT_SYMBOL(fib_default_rule_add);

static void notify_rule_change(int event, struct fib_rule *rule,
			       struct fib_rules_ops *ops, struct nlmsghdr *nlh,
			       u32 pid);
//根据协议簇在链表rules_ops中查找符合要求的struct fib_rules_ops类型的变量对于ipv4而言，即为fib4_rules_ops_template
static struct fib_rules_ops *lookup_rules_ops(struct net *net, int family)
{
	struct fib_rules_ops *ops;

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &net->rules_ops, list) {
		if (ops->family == family) {
			if (!try_module_get(ops->owner))
				ops = NULL;
			rcu_read_unlock();
			return ops;
		}
	}
	rcu_read_unlock();

	return NULL;
}

static void rules_ops_put(struct fib_rules_ops *ops)
{
	if (ops)
		module_put(ops->owner);
}

static void flush_route_cache(struct fib_rules_ops *ops)
{
	if (ops->flush_cache)
		ops->flush_cache();
}

int fib_rules_register(struct fib_rules_ops *ops)
{
	int err = -EEXIST;
	struct fib_rules_ops *o;
	struct net *net;

	net = ops->fro_net;

	if (ops->rule_size < sizeof(struct fib_rule))
		return -EINVAL;

	if (ops->match == NULL || ops->configure == NULL ||
	    ops->compare == NULL || ops->fill == NULL ||
	    ops->action == NULL)
		return -EINVAL;

	spin_lock(&net->rules_mod_lock);
	list_for_each_entry(o, &net->rules_ops, list)
		if (ops->family == o->family)
			goto errout;

	hold_net(net);
	list_add_tail_rcu(&ops->list, &net->rules_ops);
	err = 0;
errout:
	spin_unlock(&net->rules_mod_lock);

	return err;
}

EXPORT_SYMBOL_GPL(fib_rules_register);

void fib_rules_cleanup_ops(struct fib_rules_ops *ops)
{
	struct fib_rule *rule, *tmp;

	list_for_each_entry_safe(rule, tmp, &ops->rules_list, list) {
		list_del_rcu(&rule->list);
		fib_rule_put(rule);
	}
}
EXPORT_SYMBOL_GPL(fib_rules_cleanup_ops);

void fib_rules_unregister(struct fib_rules_ops *ops)
{
	struct net *net = ops->fro_net;

	spin_lock(&net->rules_mod_lock);
	list_del_rcu(&ops->list);
	fib_rules_cleanup_ops(ops);
	spin_unlock(&net->rules_mod_lock);

	synchronize_rcu();
	release_net(net);
}

EXPORT_SYMBOL_GPL(fib_rules_unregister);
//遍历传入的ops变量的rules_list链表，对于每一个fib_rule调用fib_rule_match进行fib_rule规则匹配
static int fib_rule_match(struct fib_rule *rule, struct fib_rules_ops *ops,
			  struct flowi *fl, int flags)
{
	int ret = 0;

	if (rule->ifindex && (rule->ifindex != fl->iif))//rule中存在入接口网卡设备，而匹配的入接口和该接口不一致，则直接返回
		goto out;

	if ((rule->mark ^ fl->mark) & rule->mark_mask)//判断mark值是否一样，不一样直接返回
		goto out;
	//这里的match函数指针为 fib4_rule_match()
	ret = ops->match(rule, fl, flags);
out:
	//用户配置ip rule not ,表示要取反操作
	return (rule->flags & FIB_RULE_INVERT) ? !ret : ret;
}
//这里的ops是ipv4_rules_ops_template
int fib_rules_lookup(struct fib_rules_ops *ops, struct flowi *fl,
		     int flags, struct fib_lookup_arg *arg)
{
	struct fib_rule *rule;
	int err;

	rcu_read_lock();
	//遍历所有的ip rule规则
	list_for_each_entry_rcu(rule, &ops->rules_list, list) {
jumped:
		if (!fib_rule_match(rule, ops, fl, flags))//是否匹配规则
			continue;
		//走到这个位置，说明匹配上
		if (rule->action == FR_ACT_GOTO) {//配置了ip rule xxx goto yyyy
			struct fib_rule *target;

			target = rcu_dereference(rule->ctarget);
			if (target == NULL) {
				continue;
			} else {
				rule = target;
				goto jumped;
			}
		} else if (rule->action == FR_ACT_NOP)//不做任何操作
			continue;
		else
			err = ops->action(rule, fl, flags, arg);//调用fib4_rule_action() 

		if (err != -EAGAIN) {
			fib_rule_get(rule);
			arg->rule = rule;
			goto out;
		}
	}

	err = -ESRCH;
out:
	rcu_read_unlock();

	return err;
}

EXPORT_SYMBOL_GPL(fib_rules_lookup);

static int validate_rulemsg(struct fib_rule_hdr *frh, struct nlattr **tb,
			    struct fib_rules_ops *ops)
{
	int err = -EINVAL;
	/*
	1.若源地址的长度不为0时，若tb[FRA_SRC]中为空，或者传入的地址长度与相应协议规定的地址长度不等，或者实际传递的地址的实际长度与相应协议规定的地址长度不等时，则返回-EINVAL。
	*/
	if (frh->src_len)
		if (tb[FRA_SRC] == NULL ||
		    frh->src_len > (ops->addr_size * 8) ||
		    nla_len(tb[FRA_SRC]) != ops->addr_size)
			goto errout;
	/*
	若目的地址的长度不为0时，若tb[FRA_SRC]中为空，或者传入的地址长度与相应协议规定的地址长度不等，或者实际传递的地址的实际长度与相应协议规定的地址长度不等时，则返回-EINVAL。
	*/
	if (frh->dst_len)
		if (tb[FRA_DST] == NULL ||
		    frh->dst_len > (ops->addr_size * 8) ||
		    nla_len(tb[FRA_DST]) != ops->addr_size)
			goto errout;

	err = 0;
errout:
	return err;
}
//添加ip rule规格。也就是ip rule 的处理命令
static int fib_nl_newrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	//获取netlink消息的负载
	struct fib_rule_hdr *frh = nlmsg_data(nlh);
	struct fib_rules_ops *ops = NULL;
	struct fib_rule *rule, *r, *last = NULL;
	struct nlattr *tb[FRA_MAX+1];
	int err = -EINVAL, unresolved = 0;

	if (nlh->nlmsg_len < nlmsg_msg_size(sizeof(*frh)))
		goto errout;
	/*
		根据应用层传递的协议类型，查找到相应注册的struct fib_rules_ops类型的变量对于ipv4而言，就是fib4_rules_ops_template
	*/
	ops = lookup_rules_ops(net, frh->family);
	if (ops == NULL) {
		err = -EAFNOSUPPORT;
		goto errout;
	}
	//对应用层传递的值进行解析
	err = nlmsg_parse(nlh, sizeof(*frh), tb, FRA_MAX, ops->policy);
	if (err < 0)
		goto errout;
	//并对传入的源或者目的地址值进行合理性检查
	err = validate_rulemsg(frh, tb, ops);
	if (err < 0)
		goto errout;
	//创建一个新的fib_rule缓存
	rule = kzalloc(ops->rule_size, GFP_KERNEL);
	if (rule == NULL) {
		err = -ENOMEM;
		goto errout;
	}
	//设置规则所属的命名空间
	rule->fr_net = hold_net(net);
	//设置优先级
	if (tb[FRA_PRIORITY])
		rule->pref = nla_get_u32(tb[FRA_PRIORITY]);
	//设置接口index和接口名称
	if (tb[FRA_IFNAME]) {
		struct net_device *dev;

		rule->ifindex = -1;
		nla_strlcpy(rule->ifname, tb[FRA_IFNAME], IFNAMSIZ);
		dev = __dev_get_by_name(net, rule->ifname);//通过设备名找到对应的设备
		if (dev)
			rule->ifindex = dev->ifindex;
	}
	//设置fwmark和fwmark_mask
	if (tb[FRA_FWMARK]) {
		rule->mark = nla_get_u32(tb[FRA_FWMARK]);
		if (rule->mark)
			/* compatibility: if the mark value is non-zero all bits
			 * are compared unless a mask is explicitly specified.
			 */
			rule->mark_mask = 0xFFFFFFFF;
	}

	if (tb[FRA_FWMASK])
		rule->mark_mask = nla_get_u32(tb[FRA_FWMASK]);
	//设置规则的action以及与该规则关联的路由表id，实现规则与路由表的关联
	rule->action = frh->action;
	rule->flags = frh->flags;
	rule->table = frh_get_table(frh, tb);//用户是否指定了路由表id，没有指定为0，会在下面的ops->configure()中进行创建
		/*
			当没有为策略规则配置优先级也没有默认优先级时，则会调用该协议对应的default_pref获取一个默认的优先级.
			对于ipv4，其default_pref的原理是获取的默认优先级是除0优先级的规则外，最大的可用的优先级值。
	*/
	if (!rule->pref && ops->default_pref)
		rule->pref = ops->default_pref(ops);

	err = -EINVAL;
	if (tb[FRA_GOTO]) {//ip rule xxxx goto NUMBER命名
		if (rule->action != FR_ACT_GOTO)
			goto errout_free;
		//设置goto跳转的目标路由器
		rule->target = nla_get_u32(tb[FRA_GOTO]);
		/* Backward jumps are prohibited to avoid endless loops */
		if (rule->target <= rule->pref)
			goto errout_free;
		//寻找goto跳转后的rule规则
		list_for_each_entry(r, &ops->rules_list, list) {
			if (r->pref == rule->target) {
				rule->ctarget = r;
				break;
			}
		}

		if (rule->ctarget == NULL)
			unresolved = 1;
	} else if (rule->action == FR_ACT_GOTO)
		goto errout_free;
	//调用协议对应的configure函数，对fib_rule的源、目的ip、tos等值进行配置,IPV4对应fib4_rule_configure()
	err = ops->configure(rule, skb, nlh, frh, tb);
	if (err < 0)
		goto errout_free;
	/*
		遍历规则链表，找到第一个pref值比当前刚创建的fib rule的pref值大的fib rule:
		若找到符合要求的规则，则将新创建的策略规则添加到符合要求的规则之前；若在搜索完整个链表仍没有找到符合要求的规则，则将该规则添加到当前链表已有规则的租后，即链尾。
	*/
	list_for_each_entry(r, &ops->rules_list, list) {
		if (r->pref > rule->pref)
			break;
		last = r;
	}

	fib_rule_get(rule);

	if (ops->unresolved_rules) {
		/*
		 * There are unresolved goto rules in the list, check if
		 * any of them are pointing to this new rule.
		 */
		list_for_each_entry(r, &ops->rules_list, list) {
			if (r->action == FR_ACT_GOTO &&
			    r->target == rule->pref) {
				BUG_ON(r->ctarget != NULL);
				rcu_assign_pointer(r->ctarget, rule);
				if (--ops->unresolved_rules == 0)
					break;
			}
		}
	}

	if (rule->action == FR_ACT_GOTO)
		ops->nr_goto_rules++;

	if (unresolved)
		ops->unresolved_rules++;

	if (last)
		list_add_rcu(&rule->list, &last->list);
	else
		list_add_rcu(&rule->list, &ops->rules_list);

	notify_rule_change(RTM_NEWRULE, rule, ops, nlh, NETLINK_CB(skb).pid);
	flush_route_cache(ops);
	rules_ops_put(ops);
	return 0;

errout_free:
	release_net(rule->fr_net);
	kfree(rule);
errout:
	rules_ops_put(ops);
	return err;
}

static int fib_nl_delrule(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct fib_rule_hdr *frh = nlmsg_data(nlh);
	struct fib_rules_ops *ops = NULL;
	struct fib_rule *rule, *tmp;
	struct nlattr *tb[FRA_MAX+1];
	int err = -EINVAL;

	if (nlh->nlmsg_len < nlmsg_msg_size(sizeof(*frh)))
		goto errout;
	/*
		根据应用层传递的协议类型，查找到相应注册的struct fib_rules_ops类型的变量对于ipv4而言，就是fib4_rules_ops
	*/
	ops = lookup_rules_ops(net, frh->family);
	if (ops == NULL) {
		err = -EAFNOSUPPORT;
		goto errout;
	}
	//解析引用层传递的消息
	err = nlmsg_parse(nlh, sizeof(*frh), tb, FRA_MAX, ops->policy);
	if (err < 0)
		goto errout;
	//并对传入的源或者目的地址值进行合理性检查
	err = validate_rulemsg(frh, tb, ops);
	if (err < 0)
		goto errout;
	//遍历规则链表，找到符合要求的规则
	list_for_each_entry(rule, &ops->rules_list, list) {
		if (frh->action && (frh->action != rule->action))
			continue;

		if (frh->table && (frh_get_table(frh, tb) != rule->table))
			continue;

		if (tb[FRA_PRIORITY] &&
		    (rule->pref != nla_get_u32(tb[FRA_PRIORITY])))
			continue;

		if (tb[FRA_IFNAME] &&
		    nla_strcmp(tb[FRA_IFNAME], rule->ifname))
			continue;

		if (tb[FRA_FWMARK] &&
		    (rule->mark != nla_get_u32(tb[FRA_FWMARK])))
			continue;

		if (tb[FRA_FWMASK] &&
		    (rule->mark_mask != nla_get_u32(tb[FRA_FWMASK])))
			continue;

		if (!ops->compare(rule, frh, tb))
			continue;

		if (rule->flags & FIB_RULE_PERMANENT) {//永久rule不允许被删除，例如匹配local路由表的rule
			err = -EPERM;
			goto errout;
		}
		//删除匹配的规则
		list_del_rcu(&rule->list);
		//解决goto规则相关
		if (rule->action == FR_ACT_GOTO)
			ops->nr_goto_rules--;

		/*
		 * Check if this rule is a target to any of them. If so,
		 * disable them. As this operation is eventually very
		 * expensive, it is only performed if goto rules have
		 * actually been added.
		 */
		if (ops->nr_goto_rules > 0) {
			list_for_each_entry(tmp, &ops->rules_list, list) {
				if (tmp->ctarget == rule) {
					rcu_assign_pointer(tmp->ctarget, NULL);
					ops->unresolved_rules++;
				}
			}
		}

		synchronize_rcu();
		notify_rule_change(RTM_DELRULE, rule, ops, nlh,
				   NETLINK_CB(skb).pid);//向应用层投递RTM_DELRULE消息
		fib_rule_put(rule);//减去对该fib rule的引用计数并决定是否放入fib_rule的缓存中
		flush_route_cache(ops);//刷新缓存
		rules_ops_put(ops);
		return 0;
	}

	err = -ENOENT;
errout:
	rules_ops_put(ops);
	return err;
}

static inline size_t fib_rule_nlmsg_size(struct fib_rules_ops *ops,
					 struct fib_rule *rule)
{
	size_t payload = NLMSG_ALIGN(sizeof(struct fib_rule_hdr))
			 + nla_total_size(IFNAMSIZ) /* FRA_IFNAME */
			 + nla_total_size(4) /* FRA_PRIORITY */
			 + nla_total_size(4) /* FRA_TABLE */
			 + nla_total_size(4) /* FRA_FWMARK */
			 + nla_total_size(4); /* FRA_FWMASK */

	if (ops->nlmsg_payload)
		payload += ops->nlmsg_payload(rule);

	return payload;
}

static int fib_nl_fill_rule(struct sk_buff *skb, struct fib_rule *rule,
			    u32 pid, u32 seq, int type, int flags,
			    struct fib_rules_ops *ops)
{
	struct nlmsghdr *nlh;
	struct fib_rule_hdr *frh;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*frh), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	frh = nlmsg_data(nlh);
	frh->table = rule->table;
	NLA_PUT_U32(skb, FRA_TABLE, rule->table);
	frh->res1 = 0;
	frh->res2 = 0;
	frh->action = rule->action;
	frh->flags = rule->flags;

	if (rule->action == FR_ACT_GOTO && rule->ctarget == NULL)
		frh->flags |= FIB_RULE_UNRESOLVED;

	if (rule->ifname[0]) {
		NLA_PUT_STRING(skb, FRA_IFNAME, rule->ifname);

		if (rule->ifindex == -1)
			frh->flags |= FIB_RULE_DEV_DETACHED;
	}

	if (rule->pref)
		NLA_PUT_U32(skb, FRA_PRIORITY, rule->pref);

	if (rule->mark)
		NLA_PUT_U32(skb, FRA_FWMARK, rule->mark);

	if (rule->mark_mask || rule->mark)
		NLA_PUT_U32(skb, FRA_FWMASK, rule->mark_mask);

	if (rule->target)
		NLA_PUT_U32(skb, FRA_GOTO, rule->target);

	if (ops->fill(rule, skb, nlh, frh) < 0)
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int dump_rules(struct sk_buff *skb, struct netlink_callback *cb,
		      struct fib_rules_ops *ops)
{
	int idx = 0;
	struct fib_rule *rule;

	list_for_each_entry(rule, &ops->rules_list, list) {
		if (idx < cb->args[1])
			goto skip;

		if (fib_nl_fill_rule(skb, rule, NETLINK_CB(cb->skb).pid,
				     cb->nlh->nlmsg_seq, RTM_NEWRULE,
				     NLM_F_MULTI, ops) < 0)
			break;
skip:
		idx++;
	}
	cb->args[1] = idx;
	rules_ops_put(ops);

	return skb->len;
}

static int fib_nl_dumprule(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct fib_rules_ops *ops;
	int idx = 0, family;

	family = rtnl_msg_family(cb->nlh);
	if (family != AF_UNSPEC) {
		/* Protocol specific dump request */
		ops = lookup_rules_ops(net, family);
		if (ops == NULL)
			return -EAFNOSUPPORT;

		return dump_rules(skb, cb, ops);
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &net->rules_ops, list) {
		if (idx < cb->args[0] || !try_module_get(ops->owner))
			goto skip;

		if (dump_rules(skb, cb, ops) < 0)
			break;

		cb->args[1] = 0;
	skip:
		idx++;
	}
	rcu_read_unlock();
	cb->args[0] = idx;

	return skb->len;
}

static void notify_rule_change(int event, struct fib_rule *rule,
			       struct fib_rules_ops *ops, struct nlmsghdr *nlh,
			       u32 pid)
{
	struct net *net;
	struct sk_buff *skb;
	int err = -ENOBUFS;

	net = ops->fro_net;
	skb = nlmsg_new(fib_rule_nlmsg_size(ops, rule), GFP_KERNEL);
	if (skb == NULL)
		goto errout;

	err = fib_nl_fill_rule(skb, rule, pid, nlh->nlmsg_seq, event, 0, ops);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in fib_rule_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}

	err = rtnl_notify(skb, net, pid, ops->nlgroup, nlh, GFP_KERNEL);
errout:
	if (err < 0)
		rtnl_set_sk_err(net, ops->nlgroup, err);
}

static void attach_rules(struct list_head *rules, struct net_device *dev)
{
	struct fib_rule *rule;
	//重新赋值rule->ifindex
	list_for_each_entry(rule, rules, list) {
		if (rule->ifindex == -1 &&
		    strcmp(dev->name, rule->ifname) == 0)
			rule->ifindex = dev->ifindex;
	}
}

static void detach_rules(struct list_head *rules, struct net_device *dev)
{
	struct fib_rule *rule;
	//将rule->ifindex置为-1，表示无效
	list_for_each_entry(rule, rules, list)
		if (rule->ifindex == dev->ifindex)
			rule->ifindex = -1;
}


static int fib_rules_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = ptr;
	struct net *net = dev_net(dev);
	struct fib_rules_ops *ops;

	ASSERT_RTNL();
	rcu_read_lock();

	switch (event) {
	case NETDEV_REGISTER://网卡注册
		list_for_each_entry(ops, &net->rules_ops, list)
			attach_rules(&ops->rules_list, dev);
		break;

	case NETDEV_UNREGISTER://网卡注销
		list_for_each_entry(ops, &net->rules_ops, list)
			detach_rules(&ops->rules_list, dev);
		break;
	}

	rcu_read_unlock();

	return NOTIFY_DONE;
}

static struct notifier_block fib_rules_notifier = {
	.notifier_call = fib_rules_event,
};

static int fib_rules_net_init(struct net *net)
{
	INIT_LIST_HEAD(&net->rules_ops);
	spin_lock_init(&net->rules_mod_lock);
	return 0;
}

static struct pernet_operations fib_rules_net_ops = {
	.init = fib_rules_net_init,
};

static int __init fib_rules_init(void)
{
	int err;
	//使用netlink通信机制中的NETLINK_ROUTE，用户使用ip rule add命令会触发注册好的RTM_NEWRULE消息
	//rtnl_register会将函数注册到一个全局rtnl_msg_handlers[protocol][msgtype]中,在NETLINK_ROUTE消息处理函数rtnetlink_rcv()中会根据rtnl_msg_handlers[protocol][msgtype]
	//来调用对应的函数
	rtnl_register(PF_UNSPEC, RTM_NEWRULE, fib_nl_newrule, NULL);//创建路由规则
	rtnl_register(PF_UNSPEC, RTM_DELRULE, fib_nl_delrule, NULL);//删除路由规则
	rtnl_register(PF_UNSPEC, RTM_GETRULE, NULL, fib_nl_dumprule);//获取路由规则

	err = register_netdevice_notifier(&fib_rules_notifier);//注册网卡上下线的通知链函数
	if (err < 0)
		goto fail;

	err = register_pernet_subsys(&fib_rules_net_ops);
	if (err < 0)
		goto fail_unregister;
	return 0;

fail_unregister:
	unregister_netdevice_notifier(&fib_rules_notifier);
fail:
	rtnl_unregister(PF_UNSPEC, RTM_NEWRULE);
	rtnl_unregister(PF_UNSPEC, RTM_DELRULE);
	rtnl_unregister(PF_UNSPEC, RTM_GETRULE);
	return err;
}

subsys_initcall(fib_rules_init);
