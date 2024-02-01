// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#endif

#ifndef USES_BPF_KTIME_GET_BOOT_NS
#define USES_BPF_KTIME_GET_BOOT_NS
#endif

#ifndef USES_BPF_GET_CURRENT_PID_TGID
#define USES_BPF_GET_CURRENT_PID_TGID
#endif

#ifndef USES_BPF_TAIL_CALL
#define USES_BPF_TAIL_CALL
#endif

#ifndef USES_BPF_GET_SMP_PROC_ID
#define USES_BPF_GET_SMP_PROC_ID
#endif

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_RINGBUF_RESERVE
#define USES_BPF_RINGBUF_RESERVE
#endif

#ifndef USES_BPF_RINGBUF_SUBMIT
#define USES_BPF_RINGBUF_SUBMIT
#endif

#ifndef USES_BPF_PROBE_READ_KERNEL
#define USES_BPF_PROBE_READ_KERNEL
#endif

#include "../../../helpers/interfaces/fixed_size_event.h"
#include "../../../helpers/interfaces/attached_programs.h"

// #include <bpf/bpf_helpers.h>

/* From linux tree: /include/linux/events/sched.h
 * TP_PROTO(bool preempt, struct task_struct *prev,
 *		 struct task_struct *next)
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch,
	     bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	if(sampling_logic(ctx, PPME_SCHEDSWITCH_6_E, MODERN_BPF_TRACEPOINT))
	{
		return 0;
	}
	
	/// TODO: we could avoid switches from kernel threads to kernel threads (?).

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SCHED_SWITCH_SIZE, PPME_SCHEDSWITCH_6_E))
	{
		return 0;
	}
	ringbuf__store_event_header(&ringbuf);

	// /*=============================== COLLECT PARAMETERS  ===========================*/

	// /* Parameter 1: next (type: PT_PID) */
	int64_t pid = (int64_t)extract__task_xid_nr(next, PIDTYPE_PID);
	ringbuf__store_s64(&ringbuf, (int64_t)pid);


	// /* Parameter 2: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(prev, &pgft_maj);
	ringbuf__store_u64(&ringbuf, pgft_maj);

	// /* Parameter 3: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(prev, &pgft_min);
	ringbuf__store_u64(&ringbuf, pgft_min);

	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, prev, mm);

	/* Parameter 4: vm_size (type: PT_UINT32) */
	uint32_t vm_size = extract__vm_size(mm);
	ringbuf__store_u32(&ringbuf, vm_size);

	// /* Parameter 5: vm_rss (type: PT_UINT32) */
	uint32_t vm_rss = extract__vm_rss(mm);
	ringbuf__store_u32(&ringbuf, vm_rss);

	// /* Parameter 6: vm_swap (type: PT_UINT32) */
	uint32_t vm_swap = extract__vm_swap(mm);
	ringbuf__store_u32(&ringbuf, vm_swap);

	// /*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/** Symbex driver starts here **/

#ifdef KLEE_VERIFICATION

int main(int argc, char **argv) {
	stub_init_proc_id(klee_int("proc_id"));
	__u64 pid_tgid;
	klee_make_symbolic(&pid_tgid, sizeof(pid_tgid), "pid_tgid");
	stub_init_pid_tgid(pid_tgid);
	BPF_MAP_OF_MAPS_INIT(&ringbuf_maps, &ringbuf_map, "ringbuf_maps", "processor", "ringbuf");
	BPF_MAP_INIT(&counter_maps, "counter_map", "processor", "counter_map");
	BPF_MAP_RESET(&counter_maps);

	klee_make_symbolic(&g_64bit_sampling_tracepoint_table,
	 	sizeof(g_64bit_sampling_tracepoint_table), "sampling_tracepoint_table");
	klee_make_symbolic(&is_dropping, sizeof(is_dropping), "is_dropping");

	klee_make_symbolic(&g_settings, sizeof(struct capture_settings), "global capture settings");
	uint32_t sampling_ratio;
	klee_make_symbolic(&sampling_ratio, sizeof(uint32_t), "sampling_ratio");
	klee_assume(sampling_ratio > 0);	// else div by zero, assuming userspace sets it to nonzero
	g_settings.sampling_ratio = sampling_ratio;

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

	struct task_struct t1;
	struct task_struct t2;
	struct task_struct t2_parent;

	long unsigned int maj_flt;
	klee_make_symbolic(&maj_flt, sizeof(maj_flt), "maj_flt");
	t1.maj_flt = maj_flt;

	long unsigned int min_flt;
	klee_make_symbolic(&min_flt, sizeof(min_flt), "min_flt");
	t1.min_flt = min_flt;

	t2.pid = klee_int("next_pid");
	t2.tgid = klee_int("next_tgid");
	t2.real_parent = &t2_parent;
	t2_parent.pid = klee_int("next_parent_pid");

	struct mm_struct mm;
	mm.total_vm = klee_int("vm_size");

	t1.mm = &mm;

	bool preempt = 0;


  if (____sched_switch(0, preempt, &t1, &t2))
    return 1;

	return 0;
}

#endif // KLEE_VERIFICATION