#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

/* helper macro to print out debug messages */
#define bpf_printk(fmt, ...)        \
({              \
  char ____fmt[] = fmt;       \
  bpf_trace_printk(____fmt, sizeof(____fmt),  \
       ##__VA_ARGS__);    \
})

#include "bpf_map_def.h"

#if (defined USES_BPF_MAPS) && (defined KLEE_VERIFICATION)

#ifndef REPLAY
#include "bpf/bpf_map_helper_defs.h"
#else 
#include "bpf/bpf_map_helper_defs_replay.h"
#endif 

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BPF_MAPS 10 // Just a random size for now
enum MapStubTypes { ArrayStub, MapStub, MapofMapStub };
void *bpf_map_stubs[MAX_BPF_MAPS];
enum MapStubTypes bpf_map_stub_types[MAX_BPF_MAPS];
unsigned int bpf_map_ctr = 0;

unsigned int record_calls = 0;

void bpf_begin(){ record_calls = 1;}
char *prefix; /* For tracing */

/* This is the same list of PCVs and OVs as in the contract file. This is
 * unfortunate duplication and should be fixed */

int traced_variable_type(char *variable, char **type) {
  *type = malloc(4 * sizeof(char));
  // Compare against known PCVs. None for BPF maps yet.
  if (!strcmp(variable, "bpf_map_type") ) {
    strcpy(*type, "SV");
    return 1;
  } else if (!strcmp(variable, "map")) {
    strcpy(*type, "DS");
    return 1;
  }
  return 0;
}

void bpf_map_init_stub(struct bpf_map_def *map, char *name, char *key_type, char *val_type) {
  map->map_id = bpf_map_ctr++;
  if (map->type == 2 | map->type == 6 | map->type == 14 || map->type == 16) {
    // Array, per-cpu Array, devmap, cpumap This should be in terms of the enum
    bpf_map_stubs[map->map_id] =
        array_allocate(name, val_type, map->value_size, map->max_entries);
    bpf_map_stub_types[map->map_id] = ArrayStub;
  } else if (map->type == 1 | map->type == 5 | map->type == 9) {
    // Hash/ per-cpu hash. Again, should be in terms of the enum
    bpf_map_stubs[map->map_id] =
        map_allocate(name, key_type, val_type, map->key_size, map->value_size, map->max_entries);
    bpf_map_stub_types[map->map_id] = MapStub;
  }
  else
    assert(0 && "Unsupported map type");
  return;
}

void bpf_map_of_maps_init_stub(struct bpf_map_def* outer, struct bpf_map_def* inner, char *name, char *key_type, char * val_type){
  // klee_trace_ret();
  outer->map_id = bpf_map_ctr++;
  assert(outer->type == 12 || outer->type == 13);
  bpf_map_stubs[outer->map_id] = map_of_map_allocate(inner,bpf_map_ctr);
  bpf_map_stub_types[outer->map_id] = MapofMapStub;
  assert(inner->type == 1 || inner->type == 5 || inner->type == 9);
  bpf_map_stubs[bpf_map_ctr] = map_allocate(name, key_type, val_type, inner->key_size, inner->value_size, inner->max_entries);
  bpf_map_stub_types[bpf_map_ctr] = MapStub;
  bpf_map_ctr++;
}

void bpf_map_reset_stub(struct bpf_map_def* map) {
  // klee_trace_ret();
  struct bpf_map_def *map_ptr = (struct bpf_map_def *) map;
  if (bpf_map_stub_types[map_ptr->map_id] == ArrayStub)
    array_reset(bpf_map_stubs[map_ptr->map_id]);
  else
    assert(0 && "Reset unsupported for given map type");
}
#define BPF_MAP_INIT(x,y,z,w) bpf_map_init_stub(x,y,z,w)
#define BPF_MAP_OF_MAPS_INIT(x,y,z,w,v) bpf_map_of_maps_init_stub(x,y,z,w,v)
#define BPF_MAP_RESET(x) bpf_map_reset_stub(x)
#else
#define BPF_MAP_INIT(x,y,z)
#define BPF_MAP_OF_MAPS_INIT(x,y,z,w)
#endif

/* helper functions called from eBPF programs written in C */
#ifdef USES_BPF_MAP_LOOKUP_ELEM
static __attribute__((noinline)) void *bpf_map_lookup_elem(void *map, const void *key) {
  // if(record_calls){
  //   klee_trace_ret_just_ptr(sizeof(void*));
  //   klee_add_bpf_call();
  // }
  struct bpf_map_def *map_ptr = ((struct bpf_map_def *)map);
  // TRACE_VAL((uint32_t)(map_ptr), "map", _u32)
  // TRACE_VAR(map_ptr->type, "bpf_map_type");
  if (bpf_map_stub_types[map_ptr->map_id] == ArrayStub)
    return array_lookup_elem(bpf_map_stubs[map_ptr->map_id], key);
  else if (bpf_map_stub_types[map_ptr->map_id] == MapStub)
    return map_lookup_elem(bpf_map_stubs[map_ptr->map_id], key);
  else if (bpf_map_stub_types[map_ptr->map_id] == MapofMapStub)
    return map_of_map_lookup_elem(bpf_map_stubs[map_ptr->map_id], key);
  else
    assert(0 && "Unsupported map type");
}
#else
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
  (void *) BPF_FUNC_map_lookup_elem;
#endif

#ifdef USES_BPF_MAP_UPDATE_ELEM
static __attribute__((noinline)) long bpf_map_update_elem(void *map, const void *key, const void *value,
                                __u64 flags) {
  // if(record_calls){
  //   klee_trace_ret();
  //   klee_add_bpf_call();
  // }
  struct bpf_map_def *map_ptr = ((struct bpf_map_def *)map);
  // TRACE_VAL((uint32_t)(map_ptr), "map", _u32)
  // TRACE_VAR(map_ptr->type, "bpf_map_type");
  if (bpf_map_stub_types[map_ptr->map_id] == ArrayStub)
    return array_update_elem(bpf_map_stubs[map_ptr->map_id], key, value, flags);
  else if (bpf_map_stub_types[map_ptr->map_id] == MapStub)
    return map_update_elem(bpf_map_stubs[map_ptr->map_id], key, value, flags);
  else
    assert(0 && "Unsupported map type");
}
#else
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
          unsigned long long flags) =
  (void *) BPF_FUNC_map_update_elem;
#endif

static int (*bpf_map_delete_elem)(void *map, void *key) =
  (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_map_push_elem)(void *map, void *value,
        unsigned long long flags) =
  (void *) BPF_FUNC_map_push_elem;
static int (*bpf_map_pop_elem)(void *map, void *value) =
  (void *) BPF_FUNC_map_pop_elem;
static int (*bpf_map_peek_elem)(void *map, void *value) =
  (void *) BPF_FUNC_map_peek_elem;
static int (*bpf_probe_read)(void *dst, int size, const void *unsafe_ptr) =
  (void *) BPF_FUNC_probe_read;

#ifdef USES_BPF_KTIME_GET_NS
unsigned long long last_time = 0;

static __attribute__ ((noinline)) void bpf_time_init_stub(void) {
  // if(record_calls){
  //   klee_trace_ret();
  //   klee_add_bpf_call();
  // }
  klee_make_symbolic(&last_time, sizeof(last_time), "current_time");
}

static __attribute__ ((noinline)) unsigned long long bpf_ktime_get_ns(void) {
  // if(record_calls){
  //   klee_trace_ret();
  //   klee_add_bpf_call();
  // }
  unsigned long long time;
  klee_make_symbolic(&time, sizeof(time), "current_time");
  klee_assume(last_time <= time);
  last_time = time;
  return time;
}
#define BPF_TIME_INIT() bpf_time_init_stub()
#else
static unsigned long long (*bpf_ktime_get_ns)(void) =
  (void *) BPF_FUNC_ktime_get_ns;
#endif

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
  (void *) BPF_FUNC_trace_printk;
static void (*bpf_tail_call)(void *ctx, void *map, int index) =
  (void *) BPF_FUNC_tail_call;

#ifdef USES_BPF_GET_SMP_PROC_ID
static __attribute__ ((noinline)) unsigned long long bpf_get_smp_processor_id(void){
  // if(record_calls){
  //   klee_trace_ret();
  //   klee_add_bpf_call();
  // }
  return RANDOM_NUM;
}
#else
static unsigned long long (*bpf_get_smp_processor_id)(void) =
  (void *) BPF_FUNC_get_smp_processor_id;
#endif

static unsigned long long (*bpf_get_current_pid_tgid)(void) =
  (void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
  (void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
  (void *) BPF_FUNC_get_current_comm;
static unsigned long long (*bpf_perf_event_read)(void *map,
             unsigned long long flags) =
  (void *) BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
  (void *) BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
  (void *) BPF_FUNC_redirect;
static int (*bpf_redirect_map)(void *map, int key, int flags) =
  (void *) BPF_FUNC_redirect_map;
static int (*bpf_perf_event_output)(void *ctx, void *map,
            unsigned long long flags, void *data,
            int size) =
  (void *) BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) =
  (void *) BPF_FUNC_get_stackid;
static int (*bpf_probe_write_user)(void *dst, const void *src, int size) =
  (void *) BPF_FUNC_probe_write_user;
static int (*bpf_current_task_under_cgroup)(void *map, int index) =
  (void *) BPF_FUNC_current_task_under_cgroup;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
  (void *) BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
  (void *) BPF_FUNC_skb_set_tunnel_key;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, int size) =
  (void *) BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, int size) =
  (void *) BPF_FUNC_skb_set_tunnel_opt;
static unsigned long long (*bpf_get_prandom_u32)(void) =
  (void *) BPF_FUNC_get_prandom_u32;

#ifdef USES_BPF_XDP_ADJUST_HEAD
static __attribute__((noinline)) int bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta) {
  /* Simple stub for now that only moves data pointer without a check. We assume
   * programs don't use the metadata for now */
  // if(record_calls){
  //   klee_trace_ret();
  //   klee_add_bpf_call();
  // }
  xdp_md->data += delta;
  return 0;
}
#else 
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_head;
#endif

static int (*bpf_xdp_adjust_meta)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_meta;
static int (*bpf_get_socket_cookie)(void *ctx) =
  (void *) BPF_FUNC_get_socket_cookie;
static int (*bpf_setsockopt)(void *ctx, int level, int optname, void *optval,
           int optlen) =
  (void *) BPF_FUNC_setsockopt;
static int (*bpf_getsockopt)(void *ctx, int level, int optname, void *optval,
           int optlen) =
  (void *) BPF_FUNC_getsockopt;
static int (*bpf_sock_ops_cb_flags_set)(void *ctx, int flags) =
  (void *) BPF_FUNC_sock_ops_cb_flags_set;
static int (*bpf_sk_redirect_map)(void *ctx, void *map, int key, int flags) =
  (void *) BPF_FUNC_sk_redirect_map;
static int (*bpf_sk_redirect_hash)(void *ctx, void *map, void *key, int flags) =
  (void *) BPF_FUNC_sk_redirect_hash;
static int (*bpf_sock_map_update)(void *map, void *key, void *value,
          unsigned long long flags) =
  (void *) BPF_FUNC_sock_map_update;
static int (*bpf_sock_hash_update)(void *map, void *key, void *value,
           unsigned long long flags) =
  (void *) BPF_FUNC_sock_hash_update;
static int (*bpf_perf_event_read_value)(void *map, unsigned long long flags,
          void *buf, unsigned int buf_size) =
  (void *) BPF_FUNC_perf_event_read_value;
static int (*bpf_perf_prog_read_value)(void *ctx, void *buf,
               unsigned int buf_size) =
  (void *) BPF_FUNC_perf_prog_read_value;
static int (*bpf_override_return)(void *ctx, unsigned long rc) =
  (void *) BPF_FUNC_override_return;
static int (*bpf_msg_redirect_map)(void *ctx, void *map, int key, int flags) =
  (void *) BPF_FUNC_msg_redirect_map;
static int (*bpf_msg_redirect_hash)(void *ctx,
            void *map, void *key, int flags) =
  (void *) BPF_FUNC_msg_redirect_hash;
static int (*bpf_msg_apply_bytes)(void *ctx, int len) =
  (void *) BPF_FUNC_msg_apply_bytes;
static int (*bpf_msg_cork_bytes)(void *ctx, int len) =
  (void *) BPF_FUNC_msg_cork_bytes;
static int (*bpf_msg_pull_data)(void *ctx, int start, int end, int flags) =
  (void *) BPF_FUNC_msg_pull_data;
static int (*bpf_msg_push_data)(void *ctx, int start, int end, int flags) =
  (void *) BPF_FUNC_msg_push_data;
static int (*bpf_msg_pop_data)(void *ctx, int start, int cut, int flags) =
  (void *) BPF_FUNC_msg_pop_data;
static int (*bpf_bind)(void *ctx, void *addr, int addr_len) =
  (void *) BPF_FUNC_bind;
static int (*bpf_xdp_adjust_tail)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_tail;
static int (*bpf_skb_get_xfrm_state)(void *ctx, int index, void *state,
             int size, int flags) =
  (void *) BPF_FUNC_skb_get_xfrm_state;
static int (*bpf_sk_select_reuseport)(void *ctx, void *map, void *key, __u32 flags) =
  (void *) BPF_FUNC_sk_select_reuseport;
static int (*bpf_get_stack)(void *ctx, void *buf, int size, int flags) =
  (void *) BPF_FUNC_get_stack;
static int (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params,
           int plen, __u32 flags) =
  (void *) BPF_FUNC_fib_lookup;
static int (*bpf_lwt_push_encap)(void *ctx, unsigned int type, void *hdr,
         unsigned int len) =
  (void *) BPF_FUNC_lwt_push_encap;
static int (*bpf_lwt_seg6_store_bytes)(void *ctx, unsigned int offset,
               void *from, unsigned int len) =
  (void *) BPF_FUNC_lwt_seg6_store_bytes;
static int (*bpf_lwt_seg6_action)(void *ctx, unsigned int action, void *param,
          unsigned int param_len) =
  (void *) BPF_FUNC_lwt_seg6_action;
static int (*bpf_lwt_seg6_adjust_srh)(void *ctx, unsigned int offset,
              unsigned int len) =
  (void *) BPF_FUNC_lwt_seg6_adjust_srh;
static int (*bpf_rc_repeat)(void *ctx) =
  (void *) BPF_FUNC_rc_repeat;
static int (*bpf_rc_keydown)(void *ctx, unsigned int protocol,
           unsigned long long scancode, unsigned int toggle) =
  (void *) BPF_FUNC_rc_keydown;
static unsigned long long (*bpf_get_current_cgroup_id)(void) =
  (void *) BPF_FUNC_get_current_cgroup_id;
static void *(*bpf_get_local_storage)(void *map, unsigned long long flags) =
  (void *) BPF_FUNC_get_local_storage;
static unsigned long long (*bpf_skb_cgroup_id)(void *ctx) =
  (void *) BPF_FUNC_skb_cgroup_id;
static unsigned long long (*bpf_skb_ancestor_cgroup_id)(void *ctx, int level) =
  (void *) BPF_FUNC_skb_ancestor_cgroup_id;
static struct bpf_sock *(*bpf_sk_lookup_tcp)(void *ctx,
               struct bpf_sock_tuple *tuple,
               int size, unsigned long long netns_id,
               unsigned long long flags) =
  (void *) BPF_FUNC_sk_lookup_tcp;
static struct bpf_sock *(*bpf_skc_lookup_tcp)(void *ctx,
               struct bpf_sock_tuple *tuple,
               int size, unsigned long long netns_id,
               unsigned long long flags) =
  (void *) BPF_FUNC_skc_lookup_tcp;
static struct bpf_sock *(*bpf_sk_lookup_udp)(void *ctx,
               struct bpf_sock_tuple *tuple,
               int size, unsigned long long netns_id,
               unsigned long long flags) =
  (void *) BPF_FUNC_sk_lookup_udp;
static int (*bpf_sk_release)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_sk_release;
static int (*bpf_skb_vlan_push)(void *ctx, __be16 vlan_proto, __u16 vlan_tci) =
  (void *) BPF_FUNC_skb_vlan_push;
static int (*bpf_skb_vlan_pop)(void *ctx) =
  (void *) BPF_FUNC_skb_vlan_pop;
static int (*bpf_rc_pointer_rel)(void *ctx, int rel_x, int rel_y) =
  (void *) BPF_FUNC_rc_pointer_rel;
static void (*bpf_spin_lock)(struct bpf_spin_lock *lock) =
  (void *) BPF_FUNC_spin_lock;
static void (*bpf_spin_unlock)(struct bpf_spin_lock *lock) =
  (void *) BPF_FUNC_spin_unlock;
static struct bpf_sock *(*bpf_sk_fullsock)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_sk_fullsock;
static struct bpf_tcp_sock *(*bpf_tcp_sock)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_tcp_sock;
static struct bpf_sock *(*bpf_get_listener_sock)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_get_listener_sock;
static int (*bpf_skb_ecn_set_ce)(void *ctx) =
  (void *) BPF_FUNC_skb_ecn_set_ce;
static int (*bpf_tcp_check_syncookie)(struct bpf_sock *sk,
      void *ip, int ip_len, void *tcp, int tcp_len) =
  (void *) BPF_FUNC_tcp_check_syncookie;
static int (*bpf_sysctl_get_name)(void *ctx, char *buf,
          unsigned long long buf_len,
          unsigned long long flags) =
  (void *) BPF_FUNC_sysctl_get_name;
static int (*bpf_sysctl_get_current_value)(void *ctx, char *buf,
             unsigned long long buf_len) =
  (void *) BPF_FUNC_sysctl_get_current_value;
static int (*bpf_sysctl_get_new_value)(void *ctx, char *buf,
               unsigned long long buf_len) =
  (void *) BPF_FUNC_sysctl_get_new_value;
static int (*bpf_sysctl_set_new_value)(void *ctx, const char *buf,
               unsigned long long buf_len) =
  (void *) BPF_FUNC_sysctl_set_new_value;
static int (*bpf_strtol)(const char *buf, unsigned long long buf_len,
       unsigned long long flags, long *res) =
  (void *) BPF_FUNC_strtol;
static int (*bpf_strtoul)(const char *buf, unsigned long long buf_len,
        unsigned long long flags, unsigned long *res) =
  (void *) BPF_FUNC_strtoul;
static void *(*bpf_sk_storage_get)(void *map, struct bpf_sock *sk,
           void *value, __u64 flags) =
  (void *) BPF_FUNC_sk_storage_get;
static int (*bpf_sk_storage_delete)(void *map, struct bpf_sock *sk) =
  (void *)BPF_FUNC_sk_storage_delete;
static int (*bpf_send_signal)(unsigned sig) = (void *)BPF_FUNC_send_signal;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb,
           unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
           unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
           unsigned long long off) asm("llvm.bpf.load.word");

#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)    \
  struct ____btf_map_##name {       \
    type_key key;         \
    type_val value;         \
  };              \
  struct ____btf_map_##name       \
  __attribute__ ((section(".maps." #name), used))   \
    ____btf_map_##name = { }

static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) =
  (void *) BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_load_bytes_relative)(void *ctx, int off, void *to, int len, __u32 start_header) =
  (void *) BPF_FUNC_skb_load_bytes_relative;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
  (void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) =
  (void *) BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
  (void *) BPF_FUNC_l4_csum_replace;

#ifdef USES_BPF_CSUM_DIFF

static __attribute__ ((noinline)) __s64 bpf_csum_diff(__be32 *from, __u32 from_size, __be32 *to,
                           __u32 to_size, __wsum seed) {
  __s64 csum;
  // if(record_calls){
  //   klee_trace_ret();
  //   klee_add_bpf_call();
  // }
  klee_make_symbolic(&csum, sizeof(__s64), "Updated Checksum");
  return csum;
}
#else
static int (*bpf_csum_diff)(void *from, int from_size, void *to, int to_size, int seed) =
  (void *) BPF_FUNC_csum_diff;
#endif
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
  (void *) BPF_FUNC_skb_under_cgroup;
static int (*bpf_skb_change_head)(void *, int len, int flags) =
  (void *) BPF_FUNC_skb_change_head;
static int (*bpf_skb_pull_data)(void *, int len) =
  (void *) BPF_FUNC_skb_pull_data;
static unsigned int (*bpf_get_cgroup_classid)(void *ctx) =
  (void *) BPF_FUNC_get_cgroup_classid;
static unsigned int (*bpf_get_route_realm)(void *ctx) =
  (void *) BPF_FUNC_get_route_realm;
static int (*bpf_skb_change_proto)(void *ctx, __be16 proto, __u64 flags) =
  (void *) BPF_FUNC_skb_change_proto;
static int (*bpf_skb_change_type)(void *ctx, __u32 type) =
  (void *) BPF_FUNC_skb_change_type;
static unsigned int (*bpf_get_hash_recalc)(void *ctx) =
  (void *) BPF_FUNC_get_hash_recalc;
static unsigned long long (*bpf_get_current_task)(void) =
  (void *) BPF_FUNC_get_current_task;
static int (*bpf_skb_change_tail)(void *ctx, __u32 len, __u64 flags) =
  (void *) BPF_FUNC_skb_change_tail;
static long long (*bpf_csum_update)(void *ctx, __u32 csum) =
  (void *) BPF_FUNC_csum_update;
static void (*bpf_set_hash_invalid)(void *ctx) =
  (void *) BPF_FUNC_set_hash_invalid;
static int (*bpf_get_numa_node_id)(void) =
  (void *) BPF_FUNC_get_numa_node_id;
static int (*bpf_probe_read_str)(void *ctx, __u32 size,
         const void *unsafe_ptr) =
  (void *) BPF_FUNC_probe_read_str;
static unsigned int (*bpf_get_socket_uid)(void *ctx) =
  (void *) BPF_FUNC_get_socket_uid;
static unsigned int (*bpf_set_hash)(void *ctx, __u32 hash) =
  (void *) BPF_FUNC_set_hash;
static int (*bpf_skb_adjust_room)(void *ctx, __s32 len_diff, __u32 mode,
          unsigned long long flags) =
  (void *) BPF_FUNC_skb_adjust_room;

/* Scan the ARCH passed in from ARCH env variable (see Makefile) */
#if defined(__TARGET_ARCH_x86)
  #define bpf_target_x86
  #define bpf_target_defined
#elif defined(__TARGET_ARCH_s390)
  #define bpf_target_s390
  #define bpf_target_defined
#elif defined(__TARGET_ARCH_arm)
  #define bpf_target_arm
  #define bpf_target_defined
#elif defined(__TARGET_ARCH_arm64)
  #define bpf_target_arm64
  #define bpf_target_defined
#elif defined(__TARGET_ARCH_mips)
  #define bpf_target_mips
  #define bpf_target_defined
#elif defined(__TARGET_ARCH_powerpc)
  #define bpf_target_powerpc
  #define bpf_target_defined
#elif defined(__TARGET_ARCH_sparc)
  #define bpf_target_sparc
  #define bpf_target_defined
#else
  #undef bpf_target_defined
#endif

/* Fall back to what the compiler says */
#ifndef bpf_target_defined
#if defined(__x86_64__)
  #define bpf_target_x86
#elif defined(__s390__)
  #define bpf_target_s390
#elif defined(__arm__)
  #define bpf_target_arm
#elif defined(__aarch64__)
  #define bpf_target_arm64
#elif defined(__mips__)
  #define bpf_target_mips
#elif defined(__powerpc__)
  #define bpf_target_powerpc
#elif defined(__sparc__)
  #define bpf_target_sparc
#endif
#endif

#if defined(bpf_target_x86)

#ifdef __KERNEL__
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)
#else
#ifdef __i386__
/* i386 kernel is built with -mregparm=3 */
#define PT_REGS_PARM1(x) ((x)->eax)
#define PT_REGS_PARM2(x) ((x)->edx)
#define PT_REGS_PARM3(x) ((x)->ecx)
#define PT_REGS_PARM4(x) 0
#define PT_REGS_PARM5(x) 0
#define PT_REGS_RET(x) ((x)->esp)
#define PT_REGS_FP(x) ((x)->ebp)
#define PT_REGS_RC(x) ((x)->eax)
#define PT_REGS_SP(x) ((x)->esp)
#define PT_REGS_IP(x) ((x)->eip)
#else
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rsp)
#define PT_REGS_FP(x) ((x)->rbp)
#define PT_REGS_RC(x) ((x)->rax)
#define PT_REGS_SP(x) ((x)->rsp)
#define PT_REGS_IP(x) ((x)->rip)
#endif
#endif

#elif defined(bpf_target_s390)

/* s390 provides user_pt_regs instead of struct pt_regs to userspace */
struct pt_regs;
#define PT_REGS_S390 const volatile user_pt_regs
#define PT_REGS_PARM1(x) (((PT_REGS_S390 *)(x))->gprs[2])
#define PT_REGS_PARM2(x) (((PT_REGS_S390 *)(x))->gprs[3])
#define PT_REGS_PARM3(x) (((PT_REGS_S390 *)(x))->gprs[4])
#define PT_REGS_PARM4(x) (((PT_REGS_S390 *)(x))->gprs[5])
#define PT_REGS_PARM5(x) (((PT_REGS_S390 *)(x))->gprs[6])
#define PT_REGS_RET(x) (((PT_REGS_S390 *)(x))->gprs[14])
/* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_FP(x) (((PT_REGS_S390 *)(x))->gprs[11])
#define PT_REGS_RC(x) (((PT_REGS_S390 *)(x))->gprs[2])
#define PT_REGS_SP(x) (((PT_REGS_S390 *)(x))->gprs[15])
#define PT_REGS_IP(x) (((PT_REGS_S390 *)(x))->psw.addr)

#elif defined(bpf_target_arm)

#define PT_REGS_PARM1(x) ((x)->uregs[0])
#define PT_REGS_PARM2(x) ((x)->uregs[1])
#define PT_REGS_PARM3(x) ((x)->uregs[2])
#define PT_REGS_PARM4(x) ((x)->uregs[3])
#define PT_REGS_PARM5(x) ((x)->uregs[4])
#define PT_REGS_RET(x) ((x)->uregs[14])
#define PT_REGS_FP(x) ((x)->uregs[11]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->uregs[0])
#define PT_REGS_SP(x) ((x)->uregs[13])
#define PT_REGS_IP(x) ((x)->uregs[12])

#elif defined(bpf_target_arm64)

/* arm64 provides struct user_pt_regs instead of struct pt_regs to userspace */
struct pt_regs;
#define PT_REGS_ARM64 const volatile struct user_pt_regs
#define PT_REGS_PARM1(x) (((PT_REGS_ARM64 *)(x))->regs[0])
#define PT_REGS_PARM2(x) (((PT_REGS_ARM64 *)(x))->regs[1])
#define PT_REGS_PARM3(x) (((PT_REGS_ARM64 *)(x))->regs[2])
#define PT_REGS_PARM4(x) (((PT_REGS_ARM64 *)(x))->regs[3])
#define PT_REGS_PARM5(x) (((PT_REGS_ARM64 *)(x))->regs[4])
#define PT_REGS_RET(x) (((PT_REGS_ARM64 *)(x))->regs[30])
/* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_FP(x) (((PT_REGS_ARM64 *)(x))->regs[29])
#define PT_REGS_RC(x) (((PT_REGS_ARM64 *)(x))->regs[0])
#define PT_REGS_SP(x) (((PT_REGS_ARM64 *)(x))->sp)
#define PT_REGS_IP(x) (((PT_REGS_ARM64 *)(x))->pc)

#elif defined(bpf_target_mips)

#define PT_REGS_PARM1(x) ((x)->regs[4])
#define PT_REGS_PARM2(x) ((x)->regs[5])
#define PT_REGS_PARM3(x) ((x)->regs[6])
#define PT_REGS_PARM4(x) ((x)->regs[7])
#define PT_REGS_PARM5(x) ((x)->regs[8])
#define PT_REGS_RET(x) ((x)->regs[31])
#define PT_REGS_FP(x) ((x)->regs[30]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[1])
#define PT_REGS_SP(x) ((x)->regs[29])
#define PT_REGS_IP(x) ((x)->cp0_epc)

#elif defined(bpf_target_powerpc)

#define PT_REGS_PARM1(x) ((x)->gpr[3])
#define PT_REGS_PARM2(x) ((x)->gpr[4])
#define PT_REGS_PARM3(x) ((x)->gpr[5])
#define PT_REGS_PARM4(x) ((x)->gpr[6])
#define PT_REGS_PARM5(x) ((x)->gpr[7])
#define PT_REGS_RC(x) ((x)->gpr[3])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->nip)

#elif defined(bpf_target_sparc)

#define PT_REGS_PARM1(x) ((x)->u_regs[UREG_I0])
#define PT_REGS_PARM2(x) ((x)->u_regs[UREG_I1])
#define PT_REGS_PARM3(x) ((x)->u_regs[UREG_I2])
#define PT_REGS_PARM4(x) ((x)->u_regs[UREG_I3])
#define PT_REGS_PARM5(x) ((x)->u_regs[UREG_I4])
#define PT_REGS_RET(x) ((x)->u_regs[UREG_I7])
#define PT_REGS_RC(x) ((x)->u_regs[UREG_I0])
#define PT_REGS_SP(x) ((x)->u_regs[UREG_FP])

/* Should this also be a bpf_target check for the sparc case? */
#if defined(__arch64__)
#define PT_REGS_IP(x) ((x)->tpc)
#else
#define PT_REGS_IP(x) ((x)->pc)
#endif

#endif

#if defined(bpf_target_powerpc)
#define BPF_KPROBE_READ_RET_IP(ip, ctx)   ({ (ip) = (ctx)->link; })
#define BPF_KRETPROBE_READ_RET_IP   BPF_KPROBE_READ_RET_IP
#elif defined(bpf_target_sparc)
#define BPF_KPROBE_READ_RET_IP(ip, ctx)   ({ (ip) = PT_REGS_RET(ctx); })
#define BPF_KRETPROBE_READ_RET_IP   BPF_KPROBE_READ_RET_IP
#else
#define BPF_KPROBE_READ_RET_IP(ip, ctx)   ({        \
    bpf_probe_read(&(ip), sizeof(ip), (void *)PT_REGS_RET(ctx)); })
#define BPF_KRETPROBE_READ_RET_IP(ip, ctx)  ({        \
    bpf_probe_read(&(ip), sizeof(ip),       \
        (void *)(PT_REGS_FP(ctx) + sizeof(ip))); })
#endif

#endif
