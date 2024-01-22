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

/* From linux tree: `/arch/x86/include/asm/trace/exceptions.h`
 *	 TP_PROTO(unsigned long address, struct pt_regs *regs,
 *		unsigned long error_code)
 */
#ifdef CAPTURE_PAGE_FAULTS
SEC("tp_btf/page_fault_user")
int BPF_PROG(pf_user,
	     unsigned long address, struct pt_regs *regs,
	     unsigned long error_code)
{
	if(sampling_logic(ctx, PPME_PAGE_FAULT_E, MODERN_BPF_TRACEPOINT))
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PAGE_FAULT_SIZE, PPME_PAGE_FAULT_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, address);

	/* Parameter 2: ip (type: PT_UINT64) */
	long unsigned int ip = 0;
	bpf_probe_read_kernel(&ip, sizeof(ip), (void *)regs->ip);
	ringbuf__store_u64(&ringbuf, ip);

	/* Parameter 3: error (type: PT_FLAGS32) */
	ringbuf__store_u32(&ringbuf, pf_flags_to_scap(error_code));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}
#endif

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

	struct pt_regs regs;
	long unsigned int ip;
	klee_make_symbolic(&ip, sizeof(ip), "ip");
	regs.ip = (long unsigned int)&ip;



  if (____pf_user(0, 0, &regs, 0))
    return 1;

	return 0;
}

#endif // KLEE_VERIFICATION