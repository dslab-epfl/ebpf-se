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

#ifndef USES_BPF_GET_CURRENT_TASK
#define USES_BPF_GET_CURRENT_TASK
#endif

#ifndef USES_BPF_TAIL_CALL
#define USES_BPF_TAIL_CALL
#endif

#ifndef USES_BPF_KTIME_GET_BOOT_NS
#define USES_BPF_KTIME_GET_BOOT_NS
#endif

#ifndef USES_BPF_PROBE_READ_KERNEL
#define USES_BPF_PROBE_READ_KERNEL
#endif

#include "../../../helpers/interfaces/syscalls_dispatcher.h"
#include "../../../helpers/interfaces/attached_programs.h"

#include <bpf/bpf_helpers.h>

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long id),
 */
SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter,
	     struct pt_regs *regs,
	     long syscall_id)
{
	int socketcall_syscall_id = -1;

	if(bpf_in_ia32_syscall())
	{
#if defined(__TARGET_ARCH_x86)
		if (syscall_id == __NR_ia32_socketcall)
		{
			socketcall_syscall_id = __NR_ia32_socketcall;
		}
		else
		{
			syscall_id = syscalls_dispatcher__convert_ia32_to_64(syscall_id);
			// syscalls defined only on 32 bits are dropped here.
			if(syscall_id == (uint32_t)-1)
			{
				return 0;
			}
		}
#else
		return 0;
#endif
	}
	else
	{
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	/* we convert it here in this way the syscall will be treated exactly as the original one */
	if(syscall_id == socketcall_syscall_id)
	{
		syscall_id = convert_network_syscalls(regs);
		if (syscall_id == -1)
		{
			// We can't do anything since modern bpf filler jump table is syscall indexed
			return 0;
		}
	}

	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id))
	{
		return 0;
	}

	if(sampling_logic(ctx, syscall_id, MODERN_BPF_SYSCALL))
	{
		return 0;
	}

	bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
	return 0;
}

int main(int argc, char **argv) {
	klee_make_symbolic(&g_ia32_to_64_table,
	 	sizeof(g_ia32_to_64_table), "ia32_to_64_table");
	klee_make_symbolic(&g_64bit_interesting_syscalls_table,
	 	sizeof(g_64bit_interesting_syscalls_table), "interesting_syscalls_table");
	klee_make_symbolic(&g_64bit_sampling_syscall_table,
	 	sizeof(g_64bit_sampling_syscall_table), "sampling_syscalls_table");
	klee_make_symbolic(&is_dropping, sizeof(is_dropping), "is_dropping");

	klee_make_symbolic(&g_settings, sizeof(struct capture_settings), "global capture settings");
	uint32_t sampling_ratio;
	klee_make_symbolic(&sampling_ratio, sizeof(uint32_t), "sampling_ratio");
	klee_assume(sampling_ratio > 0);	// else div by zero, assuming userspace sets it to nonzero
	g_settings.sampling_ratio = sampling_ratio;

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

	struct task_struct t;
	t.thread_info.status = klee_int("thread status");
	stub_init_current_task(&t);

	struct pt_regs regs;
  klee_make_symbolic(&regs, sizeof(struct pt_regs), "pt_regs");

	long syscall_id;
	klee_make_symbolic(&syscall_id, sizeof(long), "syscall_id");

  if (____sys_enter(0, &regs, syscall_id))
    return 1;

	return 0;
}
