/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __KERNEL_LB_H
#define __KERNEL_LB_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include "../common/parsing_helpers.h"
#include "../common/debug_tags.h"

#define MAX_OPT_WORDS 10    // 40 bytes for options
#define MAX_TARGET_COUNT 64 // max number of target servers for LB
#define REDIR_OPT_TYPE 42

struct __attribute__((packed)) eth_addr {
  unsigned char addr[ETH_ALEN];
};

struct __attribute__((packed)) redir_opt {
  __u8 type;
  __u8 size;
  __u32 ip;
  __u16 nop;
};

struct __attribute__((packed)) ipv4_psd_header {
  __u32 src_addr; /* IP address of source host. */
  __u32 dst_addr; /* IP address of destination host. */
  __u8 zero;      /* zero. */
  __u8 proto;     /* L4 protocol type. */
  __u16 len;      /* L4 length. */
};

struct __attribute__((__packed__)) crab_pkt {
  char buffer[12]; /* Buffer to make crab_pkt and katran packet look the same */
  struct redir_opt redir;
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

struct bpf_map_def SEC("maps") targets_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_TARGET_COUNT,
};

struct bpf_map_def SEC("maps") macs_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct eth_addr),
    .max_entries = MAX_TARGET_COUNT,
};

struct bpf_map_def SEC("maps") targets_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") cpu_rr_idx = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

#endif //__KERNEL_LB_H