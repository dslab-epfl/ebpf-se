#pragma once

#include "balancer_kern.h"

struct __attribute__((__packed__)) katran_pkt {
  struct iphdr ipinip;
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[500];
};

struct __attribute__((__packed__)) katran_pkt_icmp {
  struct iphdr ipinip;
  struct ethhdr ether;
  struct iphdr ipv4;
  struct icmphdr icmp;
  struct iphdr ipv4_prev;
  char payload[8];
};

struct __attribute__((__packed__)) katran_pkt_v6 {
  struct ipv6hdr ipinip;
  struct ethhdr ether;
  struct ipv6hdr ipv6;
  struct tcphdr tcp;
  char payload[500];
};

struct __attribute__((__packed__)) katran_pkt_icmp_v6 {
  struct ipv6hdr ipinip;
  struct ethhdr ether;
  struct ipv6hdr ipv6;
  struct icmp6hdr icmp6;
  struct ipv6hdr ipv6_prev;
  char payload[8];
};

enum PacketTypes {NON_IP,IPV4,IPV6,FRAGV4,FRAGV6,ICMPV4,ICMPV6};

void get_packet(enum PacketTypes type, struct xdp_md* ctx){

  if(type == IPV4 || type == FRAGV4 || type == NON_IP){
    struct katran_pkt* pkt =   malloc(sizeof(struct katran_pkt));
    klee_make_symbolic(pkt, sizeof(struct katran_pkt), "lb_pkt");
    if (type == NON_IP) {
      klee_assume(pkt->ether.h_proto != bpf_htons(ETH_P_IP));
      klee_assume(pkt->ether.h_proto != bpf_htons(ETH_P_IPV6));
    } else {
      pkt->ether.h_proto = bpf_htons(ETH_P_IP);
      pkt->ipv4.version = 4;
      pkt->ipv4.ihl = sizeof(struct iphdr) / 4;
      klee_assume(pkt->ipv4.protocol != IPPROTO_ICMP);
      if(type == FRAGV4)
        pkt->ipv4.frag_off = 1;
      else
        pkt->ipv4.frag_off = 0;
    }
    ctx->data = (long)(&(pkt->ether));
    ctx->data_end = (long)(pkt + 1);
  }
  else if(type == ICMPV4){
    struct katran_pkt_icmp* pkt =   malloc(sizeof(struct katran_pkt_icmp));
    klee_make_symbolic(pkt, sizeof(struct katran_pkt_icmp), "lb_pkt_icmp");
    pkt->ether.h_proto = bpf_htons(ETH_P_IP);
    pkt->ipv4.version = 4;
    pkt->ipv4.ihl = sizeof(struct iphdr) / 4;
    pkt->ipv4.frag_off = 0;
    pkt->ipv4.protocol = IPPROTO_ICMP;
    ctx->data = (long)(&(pkt->ether));
    ctx->data_end = (long)(pkt + 1);

  }
  else if (type == IPV6 || type == FRAGV6){
    struct katran_pkt_v6* pkt =   malloc(sizeof(struct katran_pkt_v6));
    klee_make_symbolic(pkt, sizeof(struct katran_pkt_v6), "lb_pkt_v6");
    pkt->ether.h_proto = bpf_htons(ETH_P_IPV6);
    pkt->ipv6.version = 6;
    klee_assume(pkt->ipv6.nexthdr != IPPROTO_ICMPV6);
    if(type == FRAGV6)
      pkt->ipv6.nexthdr = IPPROTO_FRAGMENT;
    ctx->data = (long)(&(pkt->ether));
    ctx->data_end = (long)(pkt + 1);
  }
  else if (type == ICMPV6){
    struct katran_pkt_icmp_v6* pkt =   malloc(sizeof(struct katran_pkt_icmp_v6));
    klee_make_symbolic(pkt, sizeof(struct katran_pkt_icmp_v6), "lb_pkt_icmp_v6");
    pkt->ether.h_proto = bpf_htons(ETH_P_IPV6);
    pkt->ipv6.version = 6;
    pkt->ipv6.nexthdr = IPPROTO_ICMPV6;
    ctx->data = (long)(&(pkt->ether));
    ctx->data_end = (long)(pkt + 1);
  }
  else{
    assert(0);
  }

}
