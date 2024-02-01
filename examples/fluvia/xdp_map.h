/*
 * Copyright (c) 2023 NTT Communications Corporation
 * Copyright (c) 2023 Takeru Hayasaka
 */

#ifndef __XDP_MAPS_H
#define __XDP_MAPS_H
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_consts.h"
#include "xdp_struct.h"

#ifdef KLEE_VERIFICATION
struct bpf_map_def SEC("maps") ipfix_probe_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct probe_data),
    .value_size = sizeof(__u64),
    .max_entries = MAX_MAP_ENTRIES,
};
#else
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, struct probe_data);
    __type(value, __u64);
} ipfix_probe_map SEC(".maps");
#endif // KLEE_VERIFICATION

#endif
