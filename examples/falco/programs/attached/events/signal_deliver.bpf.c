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

/* From linux tree: `/include/trace/events/signal.h`
 *	 TP_PROTO(int sig, struct kernel_siginfo *info, struct k_sigaction *ka)
 */
SEC("tp_btf/signal_deliver")
int BPF_PROG(signal_deliver,
	     int sig, struct kernel_siginfo *info, struct k_sigaction *ka)
{
	if(sampling_logic(ctx, PPME_SIGNALDELIVER_E, MODERN_BPF_TRACEPOINT))
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SIGNAL_DELIVER_SIZE, PPME_SIGNALDELIVER_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Try to find the source pid */
	pid_t spid = 0;

	if(info != NULL)
	{
		switch(sig)
		{
		case SIGKILL:
			spid = info->_sifields._kill._pid;
			break;

		case SIGTERM:
		case SIGHUP:
		case SIGINT:
		case SIGTSTP:
		case SIGQUIT:
		{
			int si_code = info->si_code;
			if(si_code == SI_USER ||
			   si_code == SI_QUEUE ||
			   si_code <= 0)
			{
				/* This is equivalent to `info->si_pid` where
			 * `si_pid` is a macro `_sifields._kill._pid`
				 */
				spid = info->_sifields._kill._pid;
			}
			break;
		}

		case SIGCHLD:
			spid = info->_sifields._sigchld._pid;
			break;

		default:
			spid = 0;
			break;
		}

		if(sig >= SIGRTMIN && sig <= SIGRTMAX)
		{
			spid = info->_sifields._rt._pid;
		}
	}

	/* Parameter 1: spid (type: PT_PID) */
	ringbuf__store_u64(&ringbuf, (int64_t)spid);

	/* Parameter 2: dpid (type: PT_PID) */
	ringbuf__store_u64(&ringbuf, (int64_t)bpf_get_current_pid_tgid() & 0xffffffff);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	ringbuf__store_u8(&ringbuf, (uint8_t)sig);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

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

	struct kernel_siginfo info;
	klee_make_symbolic(&info, sizeof(info), "sig_info");


  if (____signal_deliver(0, klee_int("sig"), &info, 0))
    return 1;

	return 0;
}