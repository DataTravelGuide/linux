/* L3/L4 protocol support for nf_conntrack. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 * (C) 2006-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_log.h>

static struct nf_conntrack_l4proto __rcu **nf_ct_protos[NFPROTO_NUMPROTO] __read_mostly;
struct nf_conntrack_l3proto __rcu *nf_ct_l3protos[NFPROTO_NUMPROTO] __read_mostly;
EXPORT_SYMBOL_GPL(nf_ct_l3protos);

static DEFINE_MUTEX(nf_ct_proto_mutex);

#ifdef CONFIG_SYSCTL
static int
nf_ct_register_sysctl(struct net *net,
		      struct ctl_table_header **header,
		      const char *path,
		      struct ctl_table *table)
{
	if (*header == NULL) {
		*header = register_net_sysctl(net, path, table);
		if (*header == NULL)
			return -ENOMEM;
	}

	return 0;
}

static void
nf_ct_unregister_sysctl(struct ctl_table_header **header,
			struct ctl_table **table,
			unsigned int users)
{
	if (users > 0)
		return;

	unregister_net_sysctl_table(*header);
	kfree(*table);
	*header = NULL;
	*table = NULL;
}

__printf(5, 6)
void nf_l4proto_log_invalid(const struct sk_buff *skb,
			    struct net *net,
			    u16 pf, u8 protonum,
			    const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (net->ct.sysctl_log_invalid != protonum ||
	    net->ct.sysctl_log_invalid != IPPROTO_RAW)
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	nf_log_packet(net, pf, 0, skb, NULL, NULL, NULL,
		      "nf_ct_proto_%d: %pV ", protonum, &vaf);
	va_end(args);
}
EXPORT_SYMBOL_GPL(nf_l4proto_log_invalid);

__printf(3, 4)
void nf_ct_l4proto_log_invalid(const struct sk_buff *skb,
			       const struct nf_conn *ct,
			       const char *fmt, ...)
{
	struct va_format vaf;
	struct net *net;
	va_list args;

	net = nf_ct_net(ct);
	if (likely(net->ct.sysctl_log_invalid == 0))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	nf_l4proto_log_invalid(skb, net, nf_ct_l3num(ct),
			       nf_ct_protonum(ct), "%pV", &vaf);
	va_end(args);
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_log_invalid);
#endif

const struct nf_conntrack_l4proto *
__nf_ct_l4proto_find(u_int16_t l3proto, u_int8_t l4proto)
{
	if (unlikely(l3proto >= NFPROTO_NUMPROTO || nf_ct_protos[l3proto] == NULL))
		return &nf_conntrack_l4proto_generic;

	return rcu_dereference(nf_ct_protos[l3proto][l4proto]);
}
EXPORT_SYMBOL_GPL(__nf_ct_l4proto_find);

/* this is guaranteed to always return a valid protocol helper, since
 * it falls back to generic_protocol */
const struct nf_conntrack_l3proto *
nf_ct_l3proto_find_get(u_int16_t l3proto)
{
	struct nf_conntrack_l3proto *p;

	rcu_read_lock();
	p = __nf_ct_l3proto_find(l3proto);
	if (!try_module_get(p->me))
		p = &nf_conntrack_l3proto_generic;
	rcu_read_unlock();

	return p;
}
EXPORT_SYMBOL_GPL(nf_ct_l3proto_find_get);

int
nf_ct_l3proto_try_module_get(unsigned short l3proto)
{
	const struct nf_conntrack_l3proto *p;
	int ret;

retry:	p = nf_ct_l3proto_find_get(l3proto);
	if (p == &nf_conntrack_l3proto_generic) {
		ret = request_module("nf_conntrack-%d", l3proto);
		if (!ret)
			goto retry;

		return -EPROTOTYPE;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(nf_ct_l3proto_try_module_get);

void nf_ct_l3proto_module_put(unsigned short l3proto)
{
	struct nf_conntrack_l3proto *p;

	/* rcu_read_lock not necessary since the caller holds a reference, but
	 * taken anyways to avoid lockdep warnings in __nf_ct_l3proto_find()
	 */
	rcu_read_lock();
	p = __nf_ct_l3proto_find(l3proto);
	module_put(p->me);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(nf_ct_l3proto_module_put);

static int nf_ct_netns_do_get(struct net *net, u8 nfproto)
{
	const struct nf_conntrack_l3proto *l3proto;
	int ret;

	might_sleep();

	ret = nf_ct_l3proto_try_module_get(nfproto);
	if (ret < 0)
		return ret;

	/* we already have a reference, can't fail */
	rcu_read_lock();
	l3proto = __nf_ct_l3proto_find(nfproto);
	rcu_read_unlock();

	if (!l3proto->net_ns_get)
		return 0;

	ret = l3proto->net_ns_get(net);
	if (ret < 0)
		nf_ct_l3proto_module_put(nfproto);

	return ret;
}

int nf_ct_netns_get(struct net *net, u8 nfproto)
{
	int err;

	if (nfproto == NFPROTO_INET) {
		err = nf_ct_netns_do_get(net, NFPROTO_IPV4);
		if (err < 0)
			goto err1;
		err = nf_ct_netns_do_get(net, NFPROTO_IPV6);
		if (err < 0)
			goto err2;
	} else {
		err = nf_ct_netns_do_get(net, nfproto);
		if (err < 0)
			goto err1;
	}
	return 0;

err2:
	nf_ct_netns_put(net, NFPROTO_IPV4);
err1:
	return err;
}
EXPORT_SYMBOL_GPL(nf_ct_netns_get);

static void nf_ct_netns_do_put(struct net *net, u8 nfproto)
{
	const struct nf_conntrack_l3proto *l3proto;

	might_sleep();

	/* same as nf_conntrack_netns_get(), reference assumed */
	rcu_read_lock();
	l3proto = __nf_ct_l3proto_find(nfproto);
	rcu_read_unlock();

	if (WARN_ON(!l3proto))
		return;

	if (l3proto->net_ns_put)
		l3proto->net_ns_put(net);

	nf_ct_l3proto_module_put(nfproto);
}

void nf_ct_netns_put(struct net *net, uint8_t nfproto)
{
	if (nfproto == NFPROTO_INET) {
		nf_ct_netns_do_put(net, NFPROTO_IPV4);
		nf_ct_netns_do_put(net, NFPROTO_IPV6);
	} else
		nf_ct_netns_do_put(net, nfproto);
}
EXPORT_SYMBOL_GPL(nf_ct_netns_put);

const struct nf_conntrack_l4proto *
nf_ct_l4proto_find_get(u_int16_t l3num, u_int8_t l4num)
{
	const struct nf_conntrack_l4proto *p;

	rcu_read_lock();
	p = __nf_ct_l4proto_find(l3num, l4num);
	if (!try_module_get(p->me))
		p = &nf_conntrack_l4proto_generic;
	rcu_read_unlock();

	return p;
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_find_get);

void nf_ct_l4proto_put(const struct nf_conntrack_l4proto *p)
{
	module_put(p->me);
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_put);

static int kill_l3proto(struct nf_conn *i, void *data)
{
	return nf_ct_l3num(i) == ((const struct nf_conntrack_l3proto *)data)->l3proto;
}

static int kill_l4proto(struct nf_conn *i, void *data)
{
	const struct nf_conntrack_l4proto *l4proto;
	l4proto = data;
	return nf_ct_protonum(i) == l4proto->l4proto &&
	       nf_ct_l3num(i) == l4proto->l3proto;
}

int nf_ct_l3proto_register(const struct nf_conntrack_l3proto *proto)
{
	int ret = 0;
	struct nf_conntrack_l3proto *old;

	if (proto->l3proto >= NFPROTO_NUMPROTO)
		return -EBUSY;
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	if (proto->tuple_to_nlattr && proto->nla_size == 0)
		return -EINVAL;
#endif
	mutex_lock(&nf_ct_proto_mutex);
	old = rcu_dereference_protected(nf_ct_l3protos[proto->l3proto],
					lockdep_is_held(&nf_ct_proto_mutex));
	if (old != &nf_conntrack_l3proto_generic) {
		ret = -EBUSY;
		goto out_unlock;
	}

	rcu_assign_pointer(nf_ct_l3protos[proto->l3proto], proto);

out_unlock:
	mutex_unlock(&nf_ct_proto_mutex);
	return ret;

}
EXPORT_SYMBOL_GPL(nf_ct_l3proto_register);

void nf_ct_l3proto_unregister(const struct nf_conntrack_l3proto *proto)
{
	BUG_ON(proto->l3proto >= NFPROTO_NUMPROTO);

	mutex_lock(&nf_ct_proto_mutex);
	BUG_ON(rcu_dereference_protected(nf_ct_l3protos[proto->l3proto],
					 lockdep_is_held(&nf_ct_proto_mutex)
					 ) != proto);
	rcu_assign_pointer(nf_ct_l3protos[proto->l3proto],
			   &nf_conntrack_l3proto_generic);
	mutex_unlock(&nf_ct_proto_mutex);

	synchronize_rcu();
	/* Remove all contrack entries for this protocol */
	nf_ct_iterate_destroy(kill_l3proto, (void*)proto);
}
EXPORT_SYMBOL_GPL(nf_ct_l3proto_unregister);

static struct nf_proto_net *nf_ct_l4proto_net(struct net *net,
				const struct nf_conntrack_l4proto *l4proto)
{
	if (l4proto->get_net_proto) {
		/* statically built-in protocols use static per-net */
		return l4proto->get_net_proto(net);
	} else if (l4proto->net_id) {
		/* ... and loadable protocols use dynamic per-net */
		return net_generic(net, *l4proto->net_id);
	}
	return NULL;
}

static
int nf_ct_l4proto_register_sysctl(struct net *net,
				  struct nf_proto_net *pn,
				  const struct nf_conntrack_l4proto *l4proto)
{
	int err = 0;

#ifdef CONFIG_SYSCTL
	if (pn->ctl_table != NULL) {
		err = nf_ct_register_sysctl(net,
					    &pn->ctl_table_header,
					    "net/netfilter",
					    pn->ctl_table);
		if (err < 0) {
			if (!pn->users) {
				kfree(pn->ctl_table);
				pn->ctl_table = NULL;
			}
		}
	}
#endif /* CONFIG_SYSCTL */
	return err;
}

static
void nf_ct_l4proto_unregister_sysctl(struct net *net,
				struct nf_proto_net *pn,
				const struct nf_conntrack_l4proto *l4proto)
{
#ifdef CONFIG_SYSCTL
	if (pn->ctl_table_header != NULL)
		nf_ct_unregister_sysctl(&pn->ctl_table_header,
					&pn->ctl_table,
					pn->users);
#endif /* CONFIG_SYSCTL */
}

/* FIXME: Allow NULL functions and sub in pointers to generic for
   them. --RR */
int nf_ct_l4proto_register_one(const struct nf_conntrack_l4proto *l4proto)
{
	int ret = 0;

	if (l4proto->l3proto >= ARRAY_SIZE(nf_ct_protos))
		return -EBUSY;

	if ((l4proto->to_nlattr && l4proto->nlattr_size == 0) ||
	    (l4proto->tuple_to_nlattr && !l4proto->nlattr_tuple_size))
		return -EINVAL;

	mutex_lock(&nf_ct_proto_mutex);
	if (!nf_ct_protos[l4proto->l3proto]) {
		/* l3proto may be loaded latter. */
		struct nf_conntrack_l4proto __rcu **proto_array;
		int i;

		proto_array =
			kmalloc_array(MAX_NF_CT_PROTO,
				      sizeof(struct nf_conntrack_l4proto *),
				      GFP_KERNEL);
		if (proto_array == NULL) {
			ret = -ENOMEM;
			goto out_unlock;
		}

		for (i = 0; i < MAX_NF_CT_PROTO; i++)
			RCU_INIT_POINTER(proto_array[i],
					 &nf_conntrack_l4proto_generic);

		/* Before making proto_array visible to lockless readers,
		 * we must make sure its content is committed to memory.
		 */
		smp_wmb();

		nf_ct_protos[l4proto->l3proto] = proto_array;
	} else if (rcu_dereference_protected(
			nf_ct_protos[l4proto->l3proto][l4proto->l4proto],
			lockdep_is_held(&nf_ct_proto_mutex)
			) != &nf_conntrack_l4proto_generic) {
		ret = -EBUSY;
		goto out_unlock;
	}

	rcu_assign_pointer(nf_ct_protos[l4proto->l3proto][l4proto->l4proto],
			   l4proto);
out_unlock:
	mutex_unlock(&nf_ct_proto_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_register_one);

int nf_ct_l4proto_pernet_register_one(struct net *net,
				const struct nf_conntrack_l4proto *l4proto)
{
	int ret = 0;
	struct nf_proto_net *pn = NULL;

	if (l4proto->init_net) {
		ret = l4proto->init_net(net, l4proto->l3proto);
		if (ret < 0)
			goto out;
	}

	pn = nf_ct_l4proto_net(net, l4proto);
	if (pn == NULL)
		goto out;

	ret = nf_ct_l4proto_register_sysctl(net, pn, l4proto);
	if (ret < 0)
		goto out;

	pn->users++;
out:
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_pernet_register_one);

static void __nf_ct_l4proto_unregister_one(const struct nf_conntrack_l4proto *l4proto)

{
	BUG_ON(l4proto->l3proto >= ARRAY_SIZE(nf_ct_protos));

	BUG_ON(rcu_dereference_protected(
			nf_ct_protos[l4proto->l3proto][l4proto->l4proto],
			lockdep_is_held(&nf_ct_proto_mutex)
			) != l4proto);
	rcu_assign_pointer(nf_ct_protos[l4proto->l3proto][l4proto->l4proto],
			   &nf_conntrack_l4proto_generic);
}

void nf_ct_l4proto_unregister_one(const struct nf_conntrack_l4proto *l4proto)
{
	mutex_lock(&nf_ct_proto_mutex);
	__nf_ct_l4proto_unregister_one(l4proto);
	mutex_unlock(&nf_ct_proto_mutex);

	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_unregister_one);

void nf_ct_l4proto_pernet_unregister_one(struct net *net,
				const struct nf_conntrack_l4proto *l4proto)
{
	struct nf_proto_net *pn = nf_ct_l4proto_net(net, l4proto);

	if (pn == NULL)
		return;

	pn->users--;
	nf_ct_l4proto_unregister_sysctl(net, pn, l4proto);
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_pernet_unregister_one);

int nf_ct_l4proto_register(const struct nf_conntrack_l4proto * const l4proto[],
			   unsigned int num_proto)
{
	int ret = -EINVAL, ver;
	unsigned int i;

	for (i = 0; i < num_proto; i++) {
		ret = nf_ct_l4proto_register_one(l4proto[i]);
		if (ret < 0)
			break;
	}
	if (i != num_proto) {
		ver = l4proto[i]->l3proto == PF_INET6 ? 6 : 4;
		pr_err("nf_conntrack_ipv%d: can't register l4 %d proto.\n",
		       ver, l4proto[i]->l4proto);
		nf_ct_l4proto_unregister(l4proto, i);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_register);

int nf_ct_l4proto_pernet_register(struct net *net,
				  const struct nf_conntrack_l4proto *const l4proto[],
				  unsigned int num_proto)
{
	int ret = -EINVAL;
	unsigned int i;

	for (i = 0; i < num_proto; i++) {
		ret = nf_ct_l4proto_pernet_register_one(net, l4proto[i]);
		if (ret < 0)
			break;
	}
	if (i != num_proto) {
		pr_err("nf_conntrack_proto_%d %d: pernet registration failed\n",
		       l4proto[i]->l4proto,
		       l4proto[i]->l3proto == PF_INET6 ? 6 : 4);
		nf_ct_l4proto_pernet_unregister(net, l4proto, i);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_pernet_register);

void nf_ct_l4proto_unregister(const struct nf_conntrack_l4proto * const l4proto[],
			      unsigned int num_proto)
{
	while (num_proto-- != 0)
		nf_ct_l4proto_pernet_unregister_one(net, l4proto[num_proto]);
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_pernet_unregister);

static unsigned int ipv4_helper(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct nf_conn_help *help;
	const struct nf_conntrack_helper *helper;

	/* This is where we call the helper: as the packet goes out. */
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		return NF_ACCEPT;

	help = nfct_help(ct);
	if (!help)
		return NF_ACCEPT;

	/* rcu_read_lock()ed by nf_hook_thresh */
	helper = rcu_dereference(help->helper);
	if (!helper)
		return NF_ACCEPT;

	return helper->help(skb, skb_network_offset(skb) + ip_hdrlen(skb),
			    ct, ctinfo);
}

static unsigned int ipv4_confirm(void *priv,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		goto out;

	/* adjust seqs for loopback traffic only in outgoing direction */
	if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) &&
	    !nf_is_loopback_packet(skb)) {
		if (!nf_ct_seq_adjust(skb, ct, ctinfo, ip_hdrlen(skb))) {
			NF_CT_STAT_INC_ATOMIC(nf_ct_net(ct), drop);
			return NF_DROP;
		}
	}
out:
	/* We've seen it coming out the other side: confirm it */
	return nf_conntrack_confirm(skb);
}

static unsigned int ipv4_conntrack_in(void *priv,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	return nf_conntrack_in(state->net, PF_INET, state->hook, skb);
}

static unsigned int ipv4_conntrack_local(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	if (ip_is_fragment(ip_hdr(skb))) { /* IP_NODEFRAG setsockopt set */
		enum ip_conntrack_info ctinfo;
		struct nf_conn *tmpl;

		tmpl = nf_ct_get(skb, &ctinfo);
		if (tmpl && nf_ct_is_template(tmpl)) {
			/* when skipping ct, clear templates to avoid fooling
			 * later targets/matches
			 */
			skb->_nfct = 0;
			nf_ct_put(tmpl);
		}
		return NF_ACCEPT;
	}

	return nf_conntrack_in(state->net, PF_INET, state->hook, skb);
}

/* Connection tracking may drop packets, but never alters them, so
 * make it the first hook.
 */
static const struct nf_hook_ops ipv4_conntrack_ops[] = {
	{
		.hook		= ipv4_conntrack_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK,
	},
	{
		.hook		= ipv4_conntrack_local,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_CONNTRACK,
	},
	{
		.hook		= ipv4_helper,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		.hook		= ipv4_confirm,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
	},
	{
		.hook		= ipv4_helper,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		.hook		= ipv4_confirm,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
	},
};

/* Fast function for those who don't want to parse /proc (and I don't
 * blame them).
 * Reversing the socket's dst/src point of view gives us the reply
 * mapping.
 */
static int
getorigdst(struct sock *sk, int optval, void __user *user, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	memset(&tuple, 0, sizeof(tuple));

	lock_sock(sk);
	tuple.src.u3.ip = inet->inet_rcv_saddr;
	tuple.src.u.tcp.port = inet->inet_sport;
	tuple.dst.u3.ip = inet->inet_daddr;
	tuple.dst.u.tcp.port = inet->inet_dport;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = sk->sk_protocol;
	release_sock(sk);

	/* We only do TCP and SCTP at the moment: is there a better way? */
	if (tuple.dst.protonum != IPPROTO_TCP &&
	    tuple.dst.protonum != IPPROTO_SCTP) {
		pr_debug("SO_ORIGINAL_DST: Not a TCP/SCTP socket\n");
		return -ENOPROTOOPT;
	}

	if ((unsigned int)*len < sizeof(struct sockaddr_in)) {
		pr_debug("SO_ORIGINAL_DST: len %d not %zu\n",
			 *len, sizeof(struct sockaddr_in));
		return -EINVAL;
	}

	h = nf_conntrack_find_get(sock_net(sk), &nf_ct_zone_dflt, &tuple);
	if (h) {
		struct sockaddr_in sin;
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

		sin.sin_family = AF_INET;
		sin.sin_port = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u.tcp.port;
		sin.sin_addr.s_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u3.ip;
		memset(sin.sin_zero, 0, sizeof(sin.sin_zero));

		pr_debug("SO_ORIGINAL_DST: %pI4 %u\n",
			 &sin.sin_addr.s_addr, ntohs(sin.sin_port));
		nf_ct_put(ct);
		if (copy_to_user(user, &sin, sizeof(sin)) != 0)
			return -EFAULT;
		else
			return 0;
	}
	pr_debug("SO_ORIGINAL_DST: Can't find %pI4/%u-%pI4/%u.\n",
		 &tuple.src.u3.ip, ntohs(tuple.src.u.tcp.port),
		 &tuple.dst.u3.ip, ntohs(tuple.dst.u.tcp.port));
	return -ENOENT;
}

static struct nf_sockopt_ops so_getorigdst = {
	.pf		= PF_INET,
	.get_optmin	= SO_ORIGINAL_DST,
	.get_optmax	= SO_ORIGINAL_DST + 1,
	.get		= getorigdst,
	.owner		= THIS_MODULE,
};

#if IS_ENABLED(CONFIG_IPV6)
static int
ipv6_getorigdst(struct sock *sk, int optval, void __user *user, int *len)
{
	struct nf_conntrack_tuple tuple = { .src.l3num = NFPROTO_IPV6 };
	const struct ipv6_pinfo *inet6 = inet6_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct sockaddr_in6 sin6;
	struct nf_conn *ct;
	__be32 flow_label;
	int bound_dev_if;

	lock_sock(sk);
	tuple.src.u3.in6 = sk->sk_v6_rcv_saddr;
	tuple.src.u.tcp.port = inet->inet_sport;
	tuple.dst.u3.in6 = sk->sk_v6_daddr;
	tuple.dst.u.tcp.port = inet->inet_dport;
	tuple.dst.protonum = sk->sk_protocol;
	bound_dev_if = sk->sk_bound_dev_if;
	flow_label = inet6->flow_label;
	release_sock(sk);

	if (tuple.dst.protonum != IPPROTO_TCP &&
	    tuple.dst.protonum != IPPROTO_SCTP)
		return -ENOPROTOOPT;

	if (*len < 0 || (unsigned int)*len < sizeof(sin6))
		return -EINVAL;

	h = nf_conntrack_find_get(sock_net(sk), &nf_ct_zone_dflt, &tuple);
	if (!h) {
		pr_debug("IP6T_SO_ORIGINAL_DST: Can't find %pI6c/%u-%pI6c/%u.\n",
			 &tuple.src.u3.ip6, ntohs(tuple.src.u.tcp.port),
			 &tuple.dst.u3.ip6, ntohs(tuple.dst.u.tcp.port));
		return -ENOENT;
	}

	ct = nf_ct_tuplehash_to_ctrack(h);

	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
	sin6.sin6_flowinfo = flow_label & IPV6_FLOWINFO_MASK;
	memcpy(&sin6.sin6_addr,
	       &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.in6,
	       sizeof(sin6.sin6_addr));

	nf_ct_put(ct);
	sin6.sin6_scope_id = ipv6_iface_scope_id(&sin6.sin6_addr, bound_dev_if);
	return copy_to_user(user, &sin6, sizeof(sin6)) ? -EFAULT : 0;
}

static struct nf_sockopt_ops so_getorigdst6 = {
	.pf		= NFPROTO_IPV6,
	.get_optmin	= IP6T_SO_ORIGINAL_DST,
	.get_optmax	= IP6T_SO_ORIGINAL_DST + 1,
	.get		= ipv6_getorigdst,
	.owner		= THIS_MODULE,
};

static unsigned int ipv6_confirm(void *priv,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	unsigned char pnum = ipv6_hdr(skb)->nexthdr;
	int protoff;
	__be16 frag_off;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		goto out;

	protoff = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &pnum,
				   &frag_off);
	if (protoff < 0 || (frag_off & htons(~0x7)) != 0) {
		pr_debug("proto header not found\n");
		goto out;
	}

	/* adjust seqs for loopback traffic only in outgoing direction */
	if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status) &&
	    !nf_is_loopback_packet(skb)) {
		if (!nf_ct_seq_adjust(skb, ct, ctinfo, protoff)) {
			NF_CT_STAT_INC_ATOMIC(nf_ct_net(ct), drop);
			return NF_DROP;
		}
	}
out:
	/* We've seen it coming out the other side: confirm it */
	return nf_conntrack_confirm(skb);
}

static unsigned int ipv6_conntrack_in(void *priv,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	return nf_conntrack_in(state->net, PF_INET6, state->hook, skb);
}

static unsigned int ipv6_conntrack_local(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	return nf_conntrack_in(state->net, PF_INET6, state->hook, skb);
}

static unsigned int ipv6_helper(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	const struct nf_conn_help *help;
	const struct nf_conntrack_helper *helper;
	enum ip_conntrack_info ctinfo;
	__be16 frag_off;
	int protoff;
	u8 nexthdr;

	/* This is where we call the helper: as the packet goes out. */
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		return NF_ACCEPT;

	help = nfct_help(ct);
	if (!help)
		return NF_ACCEPT;
	/* rcu_read_lock()ed by nf_hook_thresh */
	helper = rcu_dereference(help->helper);
	if (!helper)
		return NF_ACCEPT;

	nexthdr = ipv6_hdr(skb)->nexthdr;
	protoff = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr,
				   &frag_off);
	if (protoff < 0 || (frag_off & htons(~0x7)) != 0) {
		pr_debug("proto header not found\n");
		return NF_ACCEPT;
	}

	return helper->help(skb, protoff, ct, ctinfo);
}

static const struct nf_hook_ops ipv6_conntrack_ops[] = {
	{
		.hook		= ipv6_conntrack_in,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_CONNTRACK,
	},
	{
		.hook		= ipv6_conntrack_local,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_CONNTRACK,
	},
	{
		.hook		= ipv6_helper,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_CONNTRACK_HELPER,
	},
	{
		.hook		= ipv6_confirm,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_LAST,
	},
	{
		.hook		= ipv6_helper,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP6_PRI_CONNTRACK_HELPER,
	},
	{
		.hook		= ipv6_confirm,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP6_PRI_LAST - 1,
	},
};
#endif

static int nf_ct_tcp_fixup(struct nf_conn *ct, void *_nfproto)
{
	u8 nfproto = (unsigned long)_nfproto;

	if (nf_ct_l3num(ct) != nfproto)
		return 0;

	if (nf_ct_protonum(ct) == IPPROTO_TCP &&
	    ct->proto.tcp.state == TCP_CONNTRACK_ESTABLISHED) {
		ct->proto.tcp.seen[0].td_maxwin = 0;
		ct->proto.tcp.seen[1].td_maxwin = 0;
	}

	return 0;
}

static int nf_ct_netns_do_get(struct net *net, u8 nfproto)
{
	struct nf_conntrack_net *cnet = net_generic(net, nf_conntrack_net_id);
	bool fixup_needed = false;
	int err = 0;

	mutex_lock(&nf_ct_proto_mutex);

	switch (nfproto) {
	case NFPROTO_IPV4:
		cnet->users4++;
		if (cnet->users4 > 1)
			goto out_unlock;
		err = nf_defrag_ipv4_enable(net);
		if (err) {
			cnet->users4 = 0;
			goto out_unlock;
		}

		err = nf_register_net_hooks(net, ipv4_conntrack_ops,
					    ARRAY_SIZE(ipv4_conntrack_ops));
		if (err)
			cnet->users4 = 0;
		else
			fixup_needed = true;
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case NFPROTO_IPV6:
		cnet->users6++;
		if (cnet->users6 > 1)
			goto out_unlock;
		err = nf_defrag_ipv6_enable(net);
		if (err < 0) {
			cnet->users6 = 0;
			goto out_unlock;
		}

		err = nf_register_net_hooks(net, ipv6_conntrack_ops,
					    ARRAY_SIZE(ipv6_conntrack_ops));
		if (err)
			cnet->users6 = 0;
		else
			fixup_needed = true;
		break;
#endif
	default:
		err = -EPROTO;
		break;
	}
 out_unlock:
	mutex_unlock(&nf_ct_proto_mutex);

	if (fixup_needed)
		nf_ct_iterate_cleanup_net(net, nf_ct_tcp_fixup,
					  (void *)(unsigned long)nfproto, 0, 0);

	return err;
}

static void nf_ct_netns_do_put(struct net *net, u8 nfproto)
{
	struct nf_conntrack_net *cnet = net_generic(net, nf_conntrack_net_id);

	mutex_lock(&nf_ct_proto_mutex);
	switch (nfproto) {
	case NFPROTO_IPV4:
		if (cnet->users4 && (--cnet->users4 == 0))
			nf_unregister_net_hooks(net, ipv4_conntrack_ops,
						ARRAY_SIZE(ipv4_conntrack_ops));
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case NFPROTO_IPV6:
		if (cnet->users6 && (--cnet->users6 == 0))
			nf_unregister_net_hooks(net, ipv6_conntrack_ops,
						ARRAY_SIZE(ipv6_conntrack_ops));
		break;
#endif
	}

	mutex_unlock(&nf_ct_proto_mutex);

	synchronize_net();
	/* Remove all contrack entries for this protocol */
	nf_ct_iterate_destroy(kill_l4proto, (void *)l4proto);
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_unregister);

void nf_ct_l4proto_pernet_unregister(struct net *net,
				const struct nf_conntrack_l4proto *const l4proto[],
				unsigned int num_proto)
{
	while (num_proto-- != 0)
		nf_ct_l4proto_pernet_unregister_one(net, l4proto[num_proto]);
}
EXPORT_SYMBOL_GPL(nf_ct_l4proto_pernet_unregister);

int nf_conntrack_proto_pernet_init(struct net *net)
{
	int err;
	struct nf_proto_net *pn = nf_ct_l4proto_net(net,
					&nf_conntrack_l4proto_generic);

	err = nf_conntrack_l4proto_generic.init_net(net,
					nf_conntrack_l4proto_generic.l3proto);
	if (err < 0)
		return err;
	err = nf_ct_l4proto_register_sysctl(net,
					    pn,
					    &nf_conntrack_l4proto_generic);
	if (err < 0)
		return err;

	pn->users++;
	return 0;
}

void nf_conntrack_proto_pernet_fini(struct net *net)
{
	struct nf_proto_net *pn = nf_ct_l4proto_net(net,
					&nf_conntrack_l4proto_generic);

	pn->users--;
	nf_ct_l4proto_unregister_sysctl(net,
					pn,
					&nf_conntrack_l4proto_generic);
}

int nf_conntrack_proto_init(void)
{
	unsigned int i;
	for (i = 0; i < NFPROTO_NUMPROTO; i++)
		rcu_assign_pointer(nf_ct_l3protos[i],
				   &nf_conntrack_l3proto_generic);
	return 0;
}

void nf_conntrack_proto_fini(void)
{
	unsigned int i;
	/* free l3proto protocol tables */
	for (i = 0; i < ARRAY_SIZE(nf_ct_protos); i++)
		kfree(nf_ct_protos[i]);
}
