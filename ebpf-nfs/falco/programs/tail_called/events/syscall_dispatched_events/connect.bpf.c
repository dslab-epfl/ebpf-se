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

#include "../../../../helpers/interfaces/variable_size_event.h"
#include <asm-generic/errno.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(connect_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SOCKET_CONNECT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	unsigned long args[3];
	extract__network_args(args, 3, regs);

	/* Parameter 1: fd (type: PT_FD)*/
	int32_t socket_fd = (int32_t)args[0];
	auxmap__store_s64_param(auxmap, (int64_t)socket_fd);

	/* Parameter 2: addr (type: PT_SOCKADDR)*/
	unsigned long sockaddr_ptr = args[1];
	uint16_t addrlen = (uint16_t)args[2];
	auxmap__store_sockaddr_param(auxmap, sockaddr_ptr, addrlen);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
} // TODO: socket_addr reading

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(connect_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SOCKET_CONNECT_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	unsigned long args[1];
	extract__network_args(args, 1, regs);

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	int32_t socket_fd = (int32_t)args[0];

	/* Parameter 2: tuple (type: PT_SOCKTUPLE) */
	/* We need a valid sockfd to extract source data.*/
	if(ret == 0 || ret == -EINPROGRESS)
	{
		auxmap__store_socktuple_param(auxmap, socket_fd, OUTBOUND);
	}
	else
	{
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 3: fd (type: PT_FD)*/
	auxmap__store_s64_param(auxmap, (int64_t)socket_fd);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}	// TODO: SOCKFD extraction

/*=============================== EXIT EVENT ===========================*/
