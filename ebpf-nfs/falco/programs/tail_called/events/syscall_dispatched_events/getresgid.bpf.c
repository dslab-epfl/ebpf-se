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

#ifndef USES_BPF_PROBE_READ_USER
#define USES_BPF_PROBE_READ_USER
#endif

#ifdef EXIT
#ifndef USES_BPF_GET_CURRENT_TASK
#define USES_BPF_GET_CURRENT_TASK
#endif
#endif // EXIT

#include "../../../../helpers/interfaces/fixed_size_event.h"

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(getresgid_e,
	     struct pt_regs *regs,
	     long id)
{
        struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, ctx, GETRESGID_E_SIZE, PPME_SYSCALL_GETRESGID_E))
        {
                return 0;
        }

        ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

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

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

  if (____getresgid_e(0, 0, 0))
    return 1;

	return 0;
}

#endif // ENTER

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(getresgid_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
        if(!ringbuf__reserve_space(&ringbuf, ctx, GETRESGID_X_SIZE, PPME_SYSCALL_GETRESGID_X))
        {
                return 0;
        }

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

        /* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	/* Parameter 2: rgid (type: PT_GID) */
	unsigned long rgid_pointer = extract__syscall_argument(regs, 0);
	gid_t rgid;
	bpf_probe_read_user((void *)&rgid, sizeof(rgid), (void *)rgid_pointer);
	ringbuf__store_u32(&ringbuf, (uint32_t)rgid);

	/* Parameter 3: egid (type: PT_GID) */
	unsigned long egid_pointer = extract__syscall_argument(regs, 1);
	gid_t egid;
	bpf_probe_read_user((void *)&egid, sizeof(egid), (void *)egid_pointer);
	ringbuf__store_u32(&ringbuf, (uint32_t)egid);

	/* Parameter 4: sgid (type: PT_GID) */
	unsigned long sgid_pointer = extract__syscall_argument(regs, 2);
	gid_t sgid;
	bpf_probe_read_user((void *)&sgid, sizeof(sgid), (void *)sgid_pointer);
	ringbuf__store_u32(&ringbuf, (uint32_t)sgid);

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
	t.thread_info.status = 0; // force not ia32_syscall
	stub_init_current_task(&t);

	struct pt_regs regs;
  klee_make_symbolic(&regs, sizeof(struct pt_regs), "pt_regs");

	gid_t rgid;
	klee_make_symbolic(&rgid, sizeof rgid, "rgid");
	regs.di = (unsigned long) &rgid;

	gid_t egid;
	klee_make_symbolic(&egid, sizeof egid, "egid");
	regs.si = (unsigned long) &egid;

	gid_t sgid;
	klee_make_symbolic(&sgid, sizeof sgid, "sgid");
	regs.dx = (unsigned long) &sgid;

	long ret;
  klee_make_symbolic(&ret, sizeof(ret), "ret");

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

  if (____getresgid_x(0, &regs, ret))
    return 1;

	return 0;
}

#endif // EXIT

/*=============================== EXIT EVENT ===========================*/
