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

#ifndef USES_BPF_GET_CURRENT_TASK
#define USES_BPF_GET_CURRENT_TASK
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

#include "../../../../helpers/interfaces/fixed_size_event.h"

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(mmap2_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, MMAP2_E_SIZE, PPME_SYSCALL_MMAP2_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: addr (type: PT_UINT64) */
	unsigned long addr = extract__syscall_argument(regs, 0);
	ringbuf__store_u64(&ringbuf, addr);

	/* Parameter 2: length (type: PT_UINT64) */
	unsigned long length = extract__syscall_argument(regs, 1);
	ringbuf__store_u64(&ringbuf, length);

	/* Parameter 3: prot (type: PT_FLAGS32) */
	unsigned long prot = extract__syscall_argument(regs, 2);
	ringbuf__store_u32(&ringbuf, prot_flags_to_scap(prot));

	/* Parameter 4: flags (type: PT_FLAGS32) */
	unsigned long flags = extract__syscall_argument(regs, 3);
	ringbuf__store_u32(&ringbuf, mmap_flags_to_scap(flags));

	/* Paremeter 5: fd (type: PT_FD) */
	int32_t fd = (int32_t)extract__syscall_argument(regs, 4);
	ringbuf__store_s64(&ringbuf, (int64_t)fd);

	/* Parameter 6: pgoffset (type: PT_UINT64) */
	unsigned long offset = extract__syscall_argument(regs, 5);
	ringbuf__store_u64(&ringbuf, offset);

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
	t.thread_info.status = 0;
	stub_init_current_task(&t);

	struct pt_regs regs;
  klee_make_symbolic(&regs, sizeof(struct pt_regs), "pt_regs");

	get_task_btf_exists = 0;

	BPF_BOOT_TIME_INIT();

  if (____mmap2_e(0, &regs, 0))
    return 1;

	return 0;
}

#endif // ENTER

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(mmap2_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, MMAP2_X_SIZE, PPME_SYSCALL_MMAP2_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	struct task_struct *task = get_current_task();
	struct mm_struct *mm = NULL;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	uint32_t vm_size = extract__vm_size(mm);
	uint32_t rss_size = extract__vm_rss(mm);
	uint32_t swap_size = extract__vm_swap(mm);

	/* Parameter 2: vm_size (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, vm_size);

	/* Parameter 3: vm_rss (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, rss_size);

	/* Parameter 4: vm_swap (type: PT_UINT32) */
	ringbuf__store_u32(&ringbuf, swap_size);

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

	struct task_struct t;
	t.thread_info.status = klee_int("thread status");
	stub_init_current_task(&t);

	struct mm_struct mm;
	klee_make_symbolic(&mm, sizeof mm, "mm");
	t.mm = &mm;

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

  if (____mmap2_x(0, 0, 0))
    return 1;

	return 0;
}

#endif // EXIT

/*=============================== EXIT EVENT ===========================*/
