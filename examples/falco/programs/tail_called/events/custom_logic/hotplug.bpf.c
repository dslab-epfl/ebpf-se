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

#include "../../../../helpers/interfaces/fixed_size_event.h"

SEC("tp_btf/sys_enter")
int BPF_PROG(t1_hotplug_e)
{
	/* We assume that the ring buffer for CPU 0 is always there so we send the
	 * HOT-PLUG event through this buffer.
	 */
	uint32_t cpu_0 = 0;
	struct ringbuf_map *rb = bpf_map_lookup_elem(&ringbuf_maps, &cpu_0);
	if(!rb)
	{
		bpf_printk("unable to obtain the ring buffer for CPU 0");
		return 0;
	}

	struct counter_map *counter = bpf_map_lookup_elem(&counter_maps, &cpu_0);
	if(!counter)
	{
		bpf_printk("unable to obtain the counter map for CPU 0");
		return 0;
	}

	/* This counts the event seen by the drivers even if they are dropped because the buffer is full. */
	counter->n_evts++;

	/* If we are not able to reserve space we stop here
	 * the event collection.
	 */
	struct ringbuf_struct ringbuf;
	ringbuf.reserved_event_size = HOTPLUG_E_SIZE;
	ringbuf.event_type = PPME_CPU_HOTPLUG_E;
	ringbuf.data = bpf_ringbuf_reserve(rb, HOTPLUG_E_SIZE, 0);
	if(!ringbuf.data)
	{
		counter->n_drops_buffer++;
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS ===========================*/

	/* Parameter 1: cpu (type: PT_UINT32) */
	uint32_t current_cpu_id = (uint32_t)bpf_get_smp_processor_id();
	ringbuf__store_u32(&ringbuf, current_cpu_id);

	/* Parameter 2: action (type: PT_UINT32) */
	/* Right now we don't have actions we always send 0 */
	ringbuf__store_u32(&ringbuf, 0);

	/*=============================== COLLECT PARAMETERS ===========================*/

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

	get_task_btf_exists = klee_int("get_task_btf_exists");

	BPF_BOOT_TIME_INIT();

  if (____t1_hotplug_e(0))
    return 1;

	return 0;
}