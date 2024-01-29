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

#ifdef ENTER
#ifndef USES_BPF_GET_CURRENT_TASK
#define USES_BPF_GET_CURRENT_TASK
#endif
#endif // ENTER

#ifndef USES_BPF_PROBE_READ_KERNEL
#define USES_BPF_PROBE_READ_KERNEL
#endif

#include "../../../../helpers/interfaces/fixed_size_event.h"

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(close_e,
	     struct pt_regs *regs,
	     long id)
{
	if(maps__get_dropping_mode())
	{
		int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
		/* We drop the event if we are closing a negative file descriptor */
		if(fd < 0)
		{
			return 0;
		}

		struct task_struct *task = get_current_task();
		uint32_t max_fds = 0;
		BPF_CORE_READ_INTO(&max_fds, task, files, fdt, max_fds);
		/* We drop the event if the fd is >= than `max_fds` */
		if(fd >= max_fds)
		{
			return 0;
		}

		/* We drop the event if the fd is not open */
		long unsigned int entry = 0;
		long unsigned int *open_fds = BPF_CORE_READ(task, files, fdt, open_fds);
		if(open_fds == NULL)
		{
			return 0;
		}
		if(bpf_probe_read_kernel(&entry, sizeof(entry), (const void *)&(open_fds[BIT_WORD(fd)])) == 0)
		{
			if(!(1UL & (entry >> (fd & (BITS_PER_LONG - 1)))))
			{
				return 0;
			}
		}
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, CLOSE_E_SIZE, PPME_SYSCALL_CLOSE_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD)*/
	int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

#ifdef ENTER

int main(int argc, char **argv) {
	__u32 proc_id = 0;
	stub_init_proc_id(proc_id);
	__u64 pid_tgid;
	klee_make_symbolic(&pid_tgid, sizeof(pid_tgid), "pid_tgid");
	stub_init_pid_tgid(pid_tgid);
	BPF_MAP_OF_MAPS_INIT(&ringbuf_maps, &ringbuf_map, "ringbuf_maps", "processor", "ringbuf");
	BPF_MAP_INIT(&counter_maps, "counter_maps", "processor", "counter_map");
	BPF_MAP_RESET(&counter_maps);

	struct task_struct t;
	t.thread_info.status = klee_int("thread status");
	stub_init_current_task(&t);

	struct files_struct files;
	struct fdtable fdt;
#define MAX_FDS 16	// arbitrarily chosen
	long unsigned int open_fds[MAX_FDS];
	klee_make_symbolic(open_fds, sizeof(open_fds), "open_fds");

	t.files = &files;
	files.fdt = &fdt;

	fdt.max_fds = MAX_FDS;
	fdt.open_fds = open_fds;

	struct pt_regs regs;
  klee_make_symbolic(&regs, sizeof(struct pt_regs), "pt_regs");
	regs.orig_ax = __NR_bpf;

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

  if (____close_e(0, &regs, 0))
    return 1;

	return 0;
}

#endif // ENTER

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(close_x,
	     struct pt_regs *regs,
	     long ret)
{
	if(maps__get_dropping_mode() && ret < 0)
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, CLOSE_X_SIZE, PPME_SYSCALL_CLOSE_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO)*/
	ringbuf__store_s64(&ringbuf, ret);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

#ifdef EXIT

int main(int argc, char **argv) {
	__u32 proc_id = 0;
	stub_init_proc_id(proc_id);
	__u64 pid_tgid;
	klee_make_symbolic(&pid_tgid, sizeof(pid_tgid), "pid_tgid");
	stub_init_pid_tgid(pid_tgid);
	BPF_MAP_OF_MAPS_INIT(&ringbuf_maps, &ringbuf_map, "ringbuf_maps", "processor", "ringbuf");
	BPF_MAP_INIT(&counter_maps, "counter_maps", "processor", "counter_map");
	BPF_MAP_RESET(&counter_maps);

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

	long ret;
	klee_make_symbolic(&ret, sizeof ret, "ret");

  if (____close_x(0, 0, ret))
    return 1;

	return 0;
}

#endif // EXIT

/*=============================== EXIT EVENT ===========================*/
