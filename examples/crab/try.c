
#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#include "lb_kern.h"

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#endif

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *ethh;
  struct iphdr *iph;
  struct tcphdr *tcph;
  __u32 action = XDP_DROP; /* Default action */
  struct hdr_cursor nh;
  int nh_type;
  int ip_type;

  nh.pos = data;

  nh_type = parse_ethhdr(&nh, data_end, &ethh);
  if (nh_type != bpf_htons(ETH_P_IP)) {
    VIGOR_TAG(TRAFFIC_CLASS, NOT_ETHERNET);
    goto OUT;
  }
  klee_assert(nh.pos - data == ETH_HLEN);
  ip_type = parse_iphdr(&nh, data_end, &iph);
  if (ip_type == IPPROTO_UDP) {
    VIGOR_TAG(TRAFFIC_CLASS, UDP);
    goto OUT;
  }
  if (ip_type != IPPROTO_TCP) {
    VIGOR_TAG(TRAFFIC_CLASS, NOT_TCP);
    goto OUT;
  }

  if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
    action = XDP_ABORTED;
    VIGOR_TAG(TRAFFIC_CLASS, BROKEN_TCP);
    goto OUT;
  }

  iph->ttl--;
  action = XDP_TX;

OUT:
  return action;
}

#ifdef KLEE_VERIFICATION
#include <stdlib.h>

#define VIGOR_TAG(name, value)                                                 \
  do {                                                                         \
    static const char *name;                                                   \
    klee_make_symbolic(&name, sizeof(const char *), "vigor_tag_" #name);       \
    name = #value;                                                             \
  } while (0)

int main(int argc, char **argv) {

  const __u32 num_targets = 3;
  struct eth_addr dst[num_targets];
  for (uint i = 0; i < num_targets; i++) {
    for (uint j = 0; j < 6; j++) {
      dst[i].addr[j] = i;
    }
  }
  __u32 ipaddrs[num_targets];
  __u32 localhost = 2130706432;
  for (uint i = 0; i < num_targets; i++) {
    ipaddrs[i] = localhost + i;
  }

  BPF_MAP_INIT(&targets_map);
  BPF_MAP_INIT(&macs_map);
  BPF_MAP_INIT(&targets_count);
  BPF_MAP_INIT(&cpu_rr_idx);

  __u32 zero = 0, targets = num_targets;

  if (bpf_map_update_elem(&targets_count, &zero, &targets, 0) < 0)
    return -1;

  for (uint i = 0; i < num_targets; i++) {
    if (bpf_map_update_elem(&targets_map, &i, &ipaddrs[i], 0) < 0)
      return -1;
    if (bpf_map_update_elem(&macs_map, &ipaddrs[i], &dst[i], 0) < 0)
      return -1;
  }
  struct pkt *pkt = malloc(sizeof(struct pkt));
  klee_make_symbolic(pkt, sizeof(struct pkt), "user_buf");
  pkt->ether.h_proto = bpf_htons(ETH_P_IP);
  pkt->ipv4.ihl = sizeof(struct iphdr) / 4;
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;
  test.rx_queue_index = 0;

  if (xdp_prog_simple(&test))
    return 1;
  return 0;
}

#endif // KLEE_VERIFICATION
char _license[] SEC("license") = "GPL";
