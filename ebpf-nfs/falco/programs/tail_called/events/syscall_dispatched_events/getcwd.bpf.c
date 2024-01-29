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
int BPF_PROG(getcwd_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, GETCWD_E_SIZE, PPME_SYSCALL_GETCWD_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

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

  if (____getcwd_e(0, 0, 0))
    return 1;

	return 0;
}

#endif // ENTER

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(getcwd_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_GETCWD_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* we get the path only in case of success, in case of failure we would read only userspace junk */
	if(ret >= 0)
	{
		/* Parameter 2: path (type: PT_CHARBUF) */
		unsigned long path_pointer = extract__syscall_argument(regs, 0);
		auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);
	}
	else
	{
		/* Parameter 2: path (type: PT_CHARBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}	// TODO: path extraction

/*=============================== EXIT EVENT ===========================*/
