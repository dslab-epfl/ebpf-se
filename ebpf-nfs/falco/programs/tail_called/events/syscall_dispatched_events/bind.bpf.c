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

#ifndef USES_BPF_PROBE_READ_KERNEL
#define USES_BPF_PROBE_READ_KERNEL
#endif

#ifndef USES_BPF_PROBE_READ_USER
#define USES_BPF_PROBE_READ_USER
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

#ifndef USES_BPF_RINGBUF_OUTPUT
#define USES_BPF_RINGBUF_OUTPUT
#endif

#ifndef USES_BPF_RINGBUF_SUBMIT
#define USES_BPF_RINGBUF_SUBMIT
#endif

#include "../../../../helpers/interfaces/fixed_size_event.h"
#include "../../../../helpers/interfaces/variable_size_event.h"

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(bind_e,
	     struct pt_regs *regs,
	     long id)
{
	/* Collect parameters at the beginning to easily manage socketcalls */
	unsigned long args[1];
	extract__network_args(args, 1, regs);

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, BIND_E_SIZE, PPME_SOCKET_BIND_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	int32_t fd = (int32_t)args[0];
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

	struct pt_regs regs;
  klee_make_symbolic(&regs, sizeof(struct pt_regs), "pt_regs");
	regs.orig_ax = __NR_bind;

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

  if (____bind_e(0, &regs, 0))
    return 1;

	return 0;
}

#endif // ENTER

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(bind_x,
	     struct pt_regs *regs,
	     long ret)
{
	if(maps__get_dropping_mode() && ret < 0)
	{
		return 0;
	}

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_BIND_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/
	/* Collect parameters at the beginning to easily manage socketcalls */
	unsigned long args[3];
	extract__network_args(args, 3, regs);

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	unsigned long sockaddr_ptr = args[1];
	uint16_t addrlen = (uint16_t)args[2];
	auxmap__store_sockaddr_param(auxmap, sockaddr_ptr, addrlen);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

#ifdef EXIT // TODO: access requires reading a path string

int main(int argc, char **argv) {
	__u32 proc_id = 0;
	stub_init_proc_id(proc_id);
	__u64 pid_tgid;
	klee_make_symbolic(&pid_tgid, sizeof(pid_tgid), "pid_tgid");
	stub_init_pid_tgid(pid_tgid);
	BPF_MAP_OF_MAPS_INIT(&ringbuf_maps, &ringbuf_map, "ringbuf_maps", "processor", "ringbuf");
	BPF_MAP_INIT(&counter_maps, "counter_maps", "processor", "counter_map");
	BPF_MAP_RESET(&counter_maps);

	klee_make_symbolic(&is_dropping, sizeof(is_dropping), "is_dropping");

	BPF_MAP_INIT(&auxiliary_maps, "auxiliary_maps", "processor", "auxiliary_map");
	BPF_MAP_RESET(&auxiliary_maps);

	get_task_btf_exists = klee_int("get_task_btf_exists");

	struct task_struct t;
	t.thread_info.status = klee_int("thread status");
	stub_init_current_task(&t);

	struct pt_regs regs;
  klee_make_symbolic(&regs, sizeof(struct pt_regs), "pt_regs");

	struct sockaddr_un sock_addr;
	klee_make_symbolic(&sock_addr, sizeof(sock_addr), "sock_addr");
	uint16_t addrlen = sizeof(sock_addr);

	regs.cx = (unsigned long) &sock_addr;
	regs.si = (unsigned long) &sock_addr;
	regs.dx = addrlen;


	BPF_BOOT_TIME_INIT();
	long ret;
	klee_make_symbolic(&ret, sizeof(ret), "ret");

  if (____bind_x(0, &regs, ret))
    return 1;

	return 0;
}

#endif // EXIT

/*=============================== EXIT EVENT ===========================*/
