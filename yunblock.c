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

#include "logging.h"

#define PKT_ACCEPT 0
#define PKT_DROP 1
#define PKT_PROCESSED 2

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

// Netfilter hook function
static unsigned int ykb_nf_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state) {
  struct net_device *dev = NULL;
  const char *iif;
  struct ethhdr *eth, *eth2;
  struct sk_buff *skb2;
  int ret;

  // skip skb without head
  if (skb->head == NULL)
    return NF_ACCEPT;

  if (!strcmp(skb->dev->name, "lo"))
    return NF_ACCEPT;

  // Клонируем пакет для дальнейшей обработки
  skb2 = skb_copy(skb, GFP_ATOMIC);
  if (!skb2) {
    printk(KERN_ERR "failed to clone skb\n");
    return NF_DROP; // Если не удалось клонировать, просто дропаем пакет
  } else {
    printk(KERN_INFO "skb_clone to skb2\n");
    // skb_set_owner_w(skb2, skb->sk);
  }

  // skb_reset_mac_header(skb2);
  // memset(skb2->cb, 0, sizeof(skb2->cb));

  // Check if this packet has an Ethernet header
  eth = eth_hdr(skb);
  if (eth) printk(KERN_INFO "before skb  src: %pM dst: %pM\n", eth->h_source, eth->h_dest);
  eth2 = eth_hdr(skb2);
  if (eth) printk(KERN_INFO "before skb2 src: %pM dst: %pM\n", eth2->h_source, eth2->h_dest);


  struct neighbour *neigh = neigh_lookup(&arp_tbl, &ip_hdr(skb2)->daddr, skb2->dev);
  if (neigh) {
    if (neigh->nud_state & NUD_VALID) {
      memcpy(eth2->h_dest, neigh->ha, ETH_ALEN);
      // printk(KERN_INFO "resolved mac: %pM\n", eth_hdr(skb2)->h_dest);
    } else {
      printk(KERN_INFO "mac not yet resolved\n");
    }
    neigh_release(neigh);
  } else {
    printk(KERN_INFO "no neighbour entry found\n");
  }

  // Set source MAC if not set (optional but good practice)
  // if (!is_valid_ether_addr(eth2->h_source)) {
  memcpy(eth2->h_source, skb2->dev->dev_addr, ETH_ALEN);
  // printk(KERN_INFO "Set source MAC to %pM\n", eth2->h_source);
  // }
  printk(KERN_INFO "after skb  set src: %pM dst: %pM\n", eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest);
  printk(KERN_INFO "after skb2 set src: %pM dst: %pM\n", eth_hdr(skb2)->h_source, eth_hdr(skb2)->h_dest);

  // Проверяем интерфейс и другие параметры пакета перед отправкой
  if (!skb2->dev) {
    printk(KERN_ERR "no network device attached to skb\n");
    kfree_skb(skb2);
    return NF_ACCEPT; // Если нет устройства для отправки, дропаем пакет
  }

  // Отправляем клонированный пакет
  if (ip_hdr(skb2)->protocol == IPPROTO_TCP ||
      ip_hdr(skb2)->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (struct udphdr *)((u8 *)ip_hdr(skb2) + (ip_hdr(skb2)->ihl << 2));
    printk(KERN_INFO "Sending packet: len=%d, proto=%04x, src=%pI4:%u, "
                     "dst=%pI4:%u, dev=%s\n",
           skb2->len, ntohs(skb2->protocol), &ip_hdr(skb2)->saddr,
           ntohs(udph->source), &ip_hdr(skb2)->daddr, ntohs(udph->dest),
           skb2->dev->name);
  } else {
    // Handle non-TCP/UDP protocols or just print without ports
    printk(KERN_INFO
           "Sending packet: len=%d, proto=%04x, src=%pI4, dst=%pI4, dev=%s\n",
           skb2->len, ntohs(skb2->protocol), &ip_hdr(skb2)->saddr,
           &ip_hdr(skb2)->daddr, skb2->dev->name);
  }

  ret = dev_queue_xmit(skb2);
  if (ret < 0) {
    printk(KERN_ERR "failed to transmit skb: %d\n", ret);
    kfree_skb(skb2);
  } else if (ret > 0) {
    printk(KERN_ERR "failed to transmit skb: %d\n", ret);
    kfree_skb(skb2);
  } else {
    printk(KERN_INFO "sent skb2: %d", ret);
  }

  return NF_ACCEPT;
}
//   if (skb->mark & 0x4) {
//     lgerror(ret, "0x4 mark found");
//     return NF_ACCEPT;
//   }

//   ret = skb_linearize(skb);
//   if (ret < 0) {
//     lgerror(ret, "cannot linearize skb");
//     return NF_ACCEPT;
//   }

//   skb2 = skb_clone(skb, GFP_ATOMIC);

//   if (skb2->skb_iif != 0) {
//     dev = dev_get_by_index(&init_net, skb2->skb_iif);
//     if (!dev) {
//       // lgerror(ENODEV, "idx: %u skb->skb_iif local", skb->skb_iif);
//       // return NF_ACCEPT;
//     }
//     iif = dev->name;
//   } else {
//     iif = "empty";
//   }

//   dev_queue_xmit(skb2);
//   kfree_skb(skb2);
//   return NF_STOLEN;

//   lgerror(ret, ">iif: %s skb->dev->name: %s", iif, skb->dev->name);

//   if (strncmp(iif, "lo", sizeof("lo")))
//     return NF_ACCEPT;

//   if (strncmp(skb->dev->name, "lo", sizeof("lo")))
//     return NF_ACCEPT;

//   int vrd = process_packet(skb);

//   switch (vrd) {
//   case PKT_ACCEPT:
//     return NF_ACCEPT;
//   case PKT_DROP:
//     kfree_skb(skb);
//     return NF_STOLEN;
//   case PKT_PROCESSED:
//   default:
//     ret = send_raw_socket(skb);
//     if (ret < 0) {
//       lgerror(ret, "Failed to send packet");
//       return NF_ACCEPT;
//     }
//     kfree_skb(skb);
//     return NF_STOLEN;
//   }
// }

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
