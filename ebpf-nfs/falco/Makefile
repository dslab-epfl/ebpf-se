# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

include ../Makefile

# XDP_TARGETS := ./programs/attached/events/sched_switch.bpf
# XDP_FUNCTION := ____sched_switch

sys_exit_target: XDP_C := ./programs/attached/dispatchers/syscall_exit.bpf.c
sys_exit_symbex: XDP_TARGETS := syscall_exit.bpf

sys_exit_target: xdp-target
sys_exit_symbex: symbex

sys_enter_target: XDP_C := ./programs/attached/dispatchers/syscall_enter.bpf.c
sys_enter_symbex: XDP_TARGETS := syscall_enter.bpf

sys_enter_target: xdp-target
sys_enter_symbex: symbex

sched_switch_target: XDP_C := ./programs/attached/events/sched_switch.bpf.c
sched_switch_symbex: XDP_TARGETS := sched_switch.bpf

sched_switch_target: xdp-target
sched_switch_symbex: symbex

signal_deliver_target: XDP_C := ./programs/attached/events/signal_deliver.bpf.c
signal_deliver_symbex: XDP_TARGETS := signal_deliver.bpf

signal_deliver_target: xdp-target
signal_deliver_symbex: symbex

sched_process_fork_target: XDP_C := ./programs/attached/events/sched_process_fork.bpf.c
sched_process_fork_symbex: XDP_TARGETS := sched_process_fork.bpf

sched_process_fork_target: xdp-target
sched_process_fork_symbex: symbex

page_fault_kernel_target: XDP_C := ./programs/attached/events/page_fault_kernel.bpf.c
page_fault_kernel_symbex: XDP_TARGETS := page_fault_kernel.bpf

page_fault_kernel_target: xdp-target
page_fault_kernel_symbex: symbex

page_fault_user_target: XDP_C := ./programs/attached/events/page_fault_user.bpf.c
page_fault_user_symbex: XDP_TARGETS := page_fault_user.bpf

page_fault_user_target: xdp-target
page_fault_user_symbex: symbex

drop_target: XDP_C := ./programs/tail_called/events/custom_logic/drop.bpf.c
drop_symbex: XDP_TARGETS := drop.bpf

drop_target: xdp-target
drop_symbex: symbex

hotplug_target: XDP_C := ./programs/tail_called/events/custom_logic/hotplug.bpf.c
hotplug_symbex: XDP_TARGETS := hotplug.bpf

hotplug_target: xdp-target
hotplug_symbex: symbex

accept_target: XDP_C := ./programs/tail_called/events/syscall_dispatched_events/accept.bpf.c
accept_symbex: XDP_TARGETS := accept.bpf

accept_target: xdp-target
accept_symbex: symbex

sys_target: BPF_CFLAGS += -D$(PROG)
sys_target: XDP_C := ./programs/tail_called/events/syscall_dispatched_events/$(NAME).bpf.c
sys_symbex: XDP_TARGETS := $(NAME).bpf

sys_target: xdp-target
sys_symbex: symbex