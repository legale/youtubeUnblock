#ifndef KERNEL_SPACE
#error "You are trying to compile the kernel module not in the kernel space"
#endif

// Kernel module for youtubeUnblock.
// Build with make kmake 
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include "mangle.h"
#include "config.h"
#include "utils.h"
#include "logging.h"
#include "args.h"

#if defined(PKG_VERSION)
MODULE_VERSION(PKG_VERSION);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtubeUnblock");

static struct socket *rawsocket;

static struct socket *raw6socket;

static int open_raw_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET, SOCK_RAW, IPPROTO_RAW, &rawsocket);

	if (ret < 0) {
		lgerror(ret, "Unable to create raw socket\n");
		goto err;
	}

	// That's funny, but this is how it is done in the kernel
	// https://elixir.bootlin.com/linux/v3.17.7/source/net/core/sock.c#L916
	rawsocket->sk->sk_mark=config.mark;

	return 0;

err:
	return ret;
}

static void close_raw_socket(void) {
	sock_release(rawsocket);
}

static int send_raw_ipv4(const uint8_t *pkt, uint32_t pktlen) {
	int ret = 0;
	if (pktlen > AVAILABLE_MTU) return -ENOMEM;

	struct iphdr *iph;

	if ((ret = ip4_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		return ret;
	}

	struct sockaddr_in daddr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = {
			.s_addr = iph->daddr
		}
	};

	struct msghdr msg;
	struct kvec iov;

	memset(&msg, 0, sizeof(msg));

	iov.iov_base = (__u8 *)pkt;
	iov.iov_len = pktlen;

	msg.msg_flags = MSG_DONTWAIT;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;


	ret = kernel_sendmsg(rawsocket, &msg, &iov, 1, pktlen);

	return ret;
}

static int open_raw6_socket(void) {
	int ret = 0;
	ret = sock_create(AF_INET6, SOCK_RAW, IPPROTO_RAW, &raw6socket);

	if (ret < 0) {
		lgerror(ret, "Unable to create raw socket\n");
		goto err;
	}

	// That's funny, but this is how it is done in the kernel
	// https://elixir.bootlin.com/linux/v3.17.7/source/net/core/sock.c#L916
	raw6socket->sk->sk_mark=config.mark;

	return 0;

err:
	return ret;
}

static void close_raw6_socket(void) {
	sock_release(raw6socket);
}

static int send_raw_ipv6(const uint8_t *pkt, uint32_t pktlen) {
	int ret = 0;
	if (pktlen > AVAILABLE_MTU) return -ENOMEM;

	struct ip6_hdr *iph;

	if ((ret = ip6_payload_split(
	(uint8_t *)pkt, pktlen, &iph, NULL, NULL, NULL)) < 0) {
		return ret;
	}

	struct sockaddr_in6 daddr = {
		.sin6_family = AF_INET6,
		/* Always 0 for raw socket */
		.sin6_port = 0,
		.sin6_addr = iph->ip6_dst
	};

	struct kvec iov;
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	iov.iov_base = (__u8 *)pkt;
	iov.iov_len = pktlen;

	msg.msg_flags = MSG_DONTWAIT;
	msg.msg_name = &daddr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	ret = kernel_sendmsg(raw6socket, &msg, &iov, 1, pktlen);

	return ret;
}

static int send_raw_socket(const uint8_t *pkt, uint32_t pktlen) {
	int ret;

	if (pktlen > AVAILABLE_MTU) {
		lgdebug("The packet is too big and may cause issues!");

		NETBUF_ALLOC(buff1, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(buff1)) {
			lgerror(-ENOMEM, "Allocation error");
			return -ENOMEM;
		}
		NETBUF_ALLOC(buff2, MAX_PACKET_SIZE);
		if (!NETBUF_CHECK(buff2)) {
			lgerror(-ENOMEM, "Allocation error");
			NETBUF_FREE(buff2);
			return -ENOMEM;
		}
		uint32_t buff1_size = MAX_PACKET_SIZE;
		uint32_t buff2_size = MAX_PACKET_SIZE;

		if ((ret = tcp_frag(pkt, pktlen, AVAILABLE_MTU-128,
			buff1, &buff1_size, buff2, &buff2_size)) < 0) {

			goto erret_lc;
		}

		int sent = 0;
		ret = send_raw_socket(buff1, buff1_size);

		if (ret >= 0) sent += ret;
		else {
			goto erret_lc;
		}

		ret = send_raw_socket(buff2, buff2_size);
		if (ret >= 0) sent += ret;
		else {
			goto erret_lc;
		}

		NETBUF_FREE(buff1);
		NETBUF_FREE(buff2);
		return sent;
erret_lc:
		NETBUF_FREE(buff1);
		NETBUF_FREE(buff2);
		return ret;
	}
	
	int ipvx = netproto_version(pkt, pktlen);

	if (ipvx == IP4VERSION) {
		ret = send_raw_ipv4(pkt, pktlen);
	} else if (ipvx == IP6VERSION) {
		ret = send_raw_ipv6(pkt, pktlen);
	} else {
		printf("proto version %d is unsupported\n", ipvx);
		return -EINVAL;
	}

	lgtrace_addp("raw_sock_send: %d", ret);
	return ret;
}

static int delay_packet_send(const unsigned char *data, unsigned int data_len, unsigned int delay_ms) {
	lginfo("delay_packet_send won't work on current youtubeUnblock version");
	return send_raw_socket(data, data_len);
}

struct instance_config_t instance_config = {
	.send_raw_packet = send_raw_socket,
	.send_delayed_packet = delay_packet_send,
};

static int connbytes_pkts(const struct sk_buff *skb) {
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	u_int64_t pkts = 0;
	const struct nf_conn_counter *counters;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	const struct nf_conn_acct *acct;
	acct = nf_conn_acct_find(ct);
	if (!acct)
		return -1;
	counters = acct->counter;
#else 
	counters = nf_conn_acct_find(ct);
	if (!counters)
		return -1;
#endif

	pkts = atomic64_read(&counters[IP_CT_DIR_ORIGINAL].packets);

	return pkts;
}

/* If this is a Red Hat-based kernel (Red Hat, CentOS, Fedora, etc)... */
#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		const struct nf_hook_state *state) \

#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#else

#error "Sorry; this version of RHEL is not supported because it's kind of old."

#endif /* RHEL_RELEASE_CODE >= x */


/* If this NOT a RedHat-based kernel (Ubuntu, Debian, SuSE, etc)... */
#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		void *priv, \
		struct sk_buff *skb, \
		const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		const struct nf_hook_ops *ops, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
#define NF_CALLBACK(name, skb) unsigned int name( \
		unsigned int hooknum, \
		struct sk_buff *skb, \
		const struct net_device *in, \
		const struct net_device *out, \
		int (*okfn)(struct sk_buff *))

#else
#error "Linux < 3.0 isn't supported at all."

#endif /* LINUX_VERSION_CODE > n */

#endif /* RHEL or not RHEL */



static NF_CALLBACK(ykb_nf_hook, skb) {
	int ret;

	if ((skb->mark & config.mark) == config.mark) 
		goto accept;
	
	if (skb->head == NULL) 
		goto accept;
	
	if (skb->len > MAX_PACKET_SIZE)
		goto accept;

	if (config.connbytes_limit != 0 && connbytes_pkts(skb) > config.connbytes_limit)
		goto accept;

	ret = skb_linearize(skb);
	if (ret < 0) {
		lgerror(ret, "Cannot linearize");
		goto accept;
	}

	int vrd = process_packet(skb->data, skb->len);

	switch(vrd) {
		case PKT_ACCEPT:
			goto accept;
		case PKT_DROP:
			goto drop;
	}

accept:
	return NF_ACCEPT;
drop:
	kfree_skb(skb);
	return NF_STOLEN;
}


static struct nf_hook_ops ykb_nf_forward_reg __read_mostly = {
	.hook     = ykb_nf_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops ykb_nf_local_out_reg __read_mostly = {
	.hook     = ykb_nf_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};

// Аналогично для IPv6
static struct nf_hook_ops ykb6_nf_forward_reg __read_mostly = {
	.hook     = ykb_nf_hook,
	.pf       = NFPROTO_IPV6,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops ykb6_nf_local_out_reg __read_mostly = {
	.hook     = ykb_nf_hook,
	.pf       = NFPROTO_IPV6,
	.hooknum  = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};

static int __init ykb_init(void) {
	int ret = 0;
	ret = init_config(&config);
	if (ret < 0) goto err;

	ret = open_raw_socket();
	if (ret < 0) goto err;

	// Регистрация для FORWARD
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	struct net *n;
	for_each_net(n) {
		ret = nf_register_net_hook(n, &ykb_nf_forward_reg);
		if (ret < 0) { 
			lgerror(ret, "register forward net_hook");
		} else {
			lginfo("register forward net_hook successfull");
		}
	}
	#else
	ret = nf_register_hook(&ykb_nf_forward_reg);
	if (ret < 0) {
		lgerror(ret, "register forward net_hook");
	} else {
		lginfo("register forward net_hook successfull");
	}
	#endif

	// Регистрация для LOCAL_OUT
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	for_each_net(n) {
		ret = nf_register_net_hook(n, &ykb_nf_local_out_reg);
		if (ret < 0) { 
			lgerror(ret, "register local_out net_hook");
		} else {
			lginfo("register local_out net_hook successfull");
		}
	}
	#else
	ret = nf_register_hook(&ykb_nf_local_out_reg);
	if (ret < 0) {
		lgerror(ret, "register local_out net_hook");
	} else {
		lginfo("register local_out net_hook successfull");
	}
	#endif


	if (config.use_ipv6) {
		ret = open_raw6_socket();
		if (ret < 0) {
			config.use_ipv6 = 0;
			lgwarning("ipv6 disabled!");
			goto ipv6_fallback;
		}

		// Регистрация для IPv6 FORWARD
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		for_each_net(n) {
			ret = nf_register_net_hook(n, &ykb6_nf_forward_reg);
			if (ret < 0) {
				lgerror(ret, "register ipv6 forward net_hook");
			} else {
				lginfo("register ipv6 forward net_hook successfull");
			}
		}
		#else
		ret = nf_register_hook(&ykb6_nf_forward_reg);
		if (ret < 0) {
			lgerror(ret, "register ipv6 forward net_hook");
		} else {
			lginfo("register ipv6 forward net_hook successfull");
		}
		#endif

		// Регистрация для IPv6 LOCAL_OUT
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		for_each_net(n) {
			ret = nf_register_net_hook(n, &ykb6_nf_local_out_reg);
			if (ret < 0) {
				lgerror(ret, "register ipv6 local_out net_hook");
			} else {
				lginfo("register ipv6 local_out net_hook successfull");
			}
		}
		#else
		ret = nf_register_hook(&ykb6_nf_local_out_reg);
		if (ret < 0) {
			lgerror(ret, "register ipv6 local_out net_hook");
		} else {
			lginfo("register ipv6 local_out net_hook successfull");
		}
		#endif
	}

	ipv6_fallback:
	lginfo("youtubeUnblock kernel module started.\n");
	return 0;

 err:
	return ret;
}


static void __exit ykb_destroy(void) {
	if (config.use_ipv6) {
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		struct net *n;
		for_each_net(n) {
			nf_unregister_net_hook(n, &ykb6_nf_forward_reg);
			nf_unregister_net_hook(n, &ykb6_nf_local_out_reg);
		}
		#else
		nf_unregister_hook(&ykb6_nf_forward_reg);
		nf_unregister_hook(&ykb6_nf_local_out_reg);
		#endif
		close_raw6_socket();
	}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	struct net *n;
	for_each_net(n) {
		nf_unregister_net_hook(n, &ykb_nf_forward_reg);
		nf_unregister_net_hook(n, &ykb_nf_local_out_reg);
	}
	#else
	nf_unregister_hook(&ykb_nf_forward_reg);
	nf_unregister_hook(&ykb_nf_local_out_reg);
	#endif

	close_raw_socket();

	free_config(config);
	lginfo("youtubeUnblock kernel module destroyed.\n");
}

module_init(ykb_init);
module_exit(ykb_destroy);
