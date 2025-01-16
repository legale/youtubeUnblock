#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>

#include "logging.h"

#define PKT_ACCEPT 0
#define PKT_DROP 1
#define PKT_PROCESSED 2
#define YKB_MARK 0x1234

static int process_packet(struct sk_buff *skb) {
  struct iphdr *iph = ip_hdr(skb);
  struct tcphdr *tcph;
  int iphv = 0;

  // Log device name
  lgdebugmsg("Processing packet on device: %s", skb->dev->name);

  // Log IP version and parse headers
  if (iph->version == 4) {
    lgdebugmsg("Detected IPv4 packet");
    tcph = tcp_hdr(skb);
    iphv = 4;
    lgdebugmsg("IPv4 Source IP: %pI4, Destination IP: %pI4", &iph->saddr,
               &iph->daddr);
  } else if (iph->version == 6) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    tcph = (struct tcphdr *)((u8 *)ip6h + sizeof(struct ipv6hdr));
    iphv = 6;
    lgdebugmsg("IPv6 Source IP: %pI6, Destination IP: %pI6", &ip6h->saddr,
               &ip6h->daddr);
  } else {
    lgerror(-EINVAL, "Unsupported IP version");
    return PKT_ACCEPT;
  }

  // Check if it's a TCP packet
  if (tcph->doff < 5) { // TCP header length must be at least 5 32-bit words
    lgerror(-EINVAL, "Invalid TCP header length: %u", tcph->doff);
    return PKT_ACCEPT;
  }

  // Log TCP header details
  lgdebugmsg("TCP Source Port: %u, Destination Port: %u", ntohs(tcph->source),
             ntohs(tcph->dest));
  lgdebugmsg("TCP Sequence Number: %u, Acknowledgment Number: %u",
             ntohl(tcph->seq), ntohl(tcph->ack_seq));
  lgdebugmsg("TCP Flags: SYN=%d, ACK=%d, FIN=%d, RST=%d", (tcph->syn != 0),
             (tcph->ack != 0), (tcph->fin != 0), (tcph->rst != 0));

  // Randomly change the sequence number
  u32 original_seq = tcph->seq;
  u32 new_seq =
      original_seq +
      (get_random_u32() % 1000); // Add random number between 0 and 999 to seq
  tcph->seq = htonl(new_seq);

  // Log sequence modification
  lgdebugmsg("TCP Sequence Number modified from %u to %u", ntohl(original_seq),
             ntohl(new_seq));

  // Update checksum
  if (iphv == 4) {
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(
        iph->saddr, iph->daddr, ntohs(iph->tot_len) - (iph->ihl << 2),
        IPPROTO_TCP,
        csum_partial(tcph, ntohs(iph->tot_len) - (iph->ihl << 2), 0));
    lgdebugmsg("Updated IPv4 and TCP checksums");
  } else if (iphv == 6) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    tcph->check = 0;
    tcph->check = csum_ipv6_magic(
        &ip6h->saddr, &ip6h->daddr, ntohs(ip6h->payload_len), IPPROTO_TCP,
        csum_partial(tcph, ntohs(ip6h->payload_len), 0));
    lgdebugmsg("Updated IPv6 and TCP checksums");
  }

  skb->mark |= 0x4;
  lgdebugmsg("Packet processing complete for device: %s", skb->dev->name);

  return PKT_ACCEPT;
}

// Function to send raw socket (unchanged)
static int send_raw_socket(struct sk_buff *skb) {
  // struct net_device *dev = NULL;
  int ret = 0;

  // dev = dev_get_by_index(&init_net, skb->skb_iif);
  // if (!dev) {
  // lgerror(ENODEV, "No device found for transmission");
  // return ENODEV;
  // }

  // skb->protocol = eth_type_trans(skb, dev);
  // skb->dev = dev;

  // ret = skb_linearize(skb);
  // if (ret < 0) {
  // lgerror(ret, "Cannot linearize skb");
  // dev_put(dev);
  // return ret;
  // }

  printk(KERN_WARNING "before_xmit");

  // ret = dev_queue_xmit(skb);
  lgerror(ret, "dev_queue_xmit: %d", ret);
  if (ret < 0) {
    lgerror(ret, "Failed to transmit packet");
  }

  return ret;
}

static unsigned int ykb_nf_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state) {
    struct net_device *dev = skb->dev;
    struct sk_buff *skb2 = NULL;
    struct ethhdr *eth = NULL, *eth2 = NULL;
    struct neighbour *neigh = NULL;
    struct rtable *rt = NULL;
    struct flowi4 fl4;
    int ret;

    if (!skb || !dev || !skb->head) {
        printk(KERN_ERR "skb or dev is invalid\n");
        return NF_ACCEPT;
    }

    if (!strcmp(dev->name, "lo"))
        return NF_ACCEPT;

    if (skb->mark == YKB_MARK) {
        printk(KERN_INFO "Packet already marked, skipping...\n");
        return NF_ACCEPT;
    }

    if (skb->protocol != htons(ETH_P_IP)) {
        printk(KERN_INFO "Skipping non-IPv4 packet, skb->protocol: 0x%04x\n", ntohs(skb->protocol));
        return NF_ACCEPT;
    }

    // Создаем новый skb с достаточным местом для eth
    skb2 = skb_copy_expand(skb, LL_RESERVED_SPACE(dev), 0, GFP_ATOMIC);
    if (!skb2) {
        printk(KERN_ERR "Failed to clone and expand skb\n");
        return NF_ACCEPT;
    }

    // Устанавливаем устройство для нового skb
    skb2->dev = dev;

    // Получаем маршрут
    memset(&fl4, 0, sizeof(fl4));
    struct iphdr *iph = ip_hdr(skb2);
    if (!iph) {
        printk(KERN_ERR "No valid IP header\n");
        kfree_skb(skb2);
        return NF_ACCEPT;
    }

    fl4.daddr = iph->daddr;
    rt = ip_route_output_key(dev_net(skb2->dev), &fl4);
    if (IS_ERR(rt)) {
        printk(KERN_ERR "Failed to get route for destination IP: %pI4\n", &fl4.daddr);
        kfree_skb(skb2);
        return NF_ACCEPT;
    }

    // Получаем MAC-адрес назначения через ARP
    neigh = neigh_lookup(&arp_tbl, &iph->daddr, rt->dst.dev);
    if (!neigh || !(neigh->nud_state & NUD_VALID)) {
        printk(KERN_INFO "MAC not yet resolved or neigh is invalid\n");
        if (neigh) 
            neigh_release(neigh);
        ip_rt_put(rt);
        kfree_skb(skb2);
        return NF_ACCEPT;
    }

    // Сдвигаем указатели для добавления Ethernet-заголовка
    skb_push(skb2, ETH_HLEN);
    skb_reset_mac_header(skb2);
    
    // Заполняем Ethernet-заголовок
    eth2 = (struct ethhdr *)skb_mac_header(skb2);
    memcpy(eth2->h_source, dev->dev_addr, ETH_ALEN);
    memcpy(eth2->h_dest, neigh->ha, ETH_ALEN);
    eth2->h_proto = htons(ETH_P_IP);

    // Освобождаем ресурсы
    neigh_release(neigh);
    ip_rt_put(rt);

    // Добавляем метку
    skb2->mark = YKB_MARK;

    printk(KERN_INFO "sending skb with MAC src: %pM dst: %pM proto: 0x%04x\n",
           eth2->h_source, eth2->h_dest, ntohs(eth2->h_proto));

    // Отправляем пакет
    ret = dev_queue_xmit(skb2);
    if (ret < 0) {
        printk(KERN_ERR "failed to send skb2\n");
        kfree_skb(skb2);
    } else {
        printk(KERN_INFO "sent\n");
    }

    return NF_ACCEPT;
}

// Netfilter hook operations
static struct nf_hook_ops ykb_nf_reg __read_mostly = {
    .hook = ykb_nf_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_MANGLE,
};

// Module initialization
static int __init ykb_init(void) {
  int ret = nf_register_net_hook(&init_net, &ykb_nf_reg);
  if (ret < 0) {
    lgerror(ret, "failed to register net_hook");
    return ret;
  }

  lginfo("youtubeUnblock kernel module started.\n");
  return 0;
}

// Module cleanup
static void __exit ykb_deinit(void) {
  nf_unregister_net_hook(&init_net, &ykb_nf_reg);
  lginfo("youtubeUnblock kernel module unloaded.\n");
}

module_init(ykb_init);
module_exit(ykb_deinit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vadim Vetrov <vetrovvd@gmail.com>");
MODULE_DESCRIPTION("Linux kernel module for youtubeUnblock");
