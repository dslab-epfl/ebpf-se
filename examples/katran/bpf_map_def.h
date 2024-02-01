#ifndef __BPF_MAP_DEF_H
#define __BPF_MAP_DEF_H

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int inner_map_idx;
  unsigned int numa_node;
  unsigned int map_id;
};

#endif