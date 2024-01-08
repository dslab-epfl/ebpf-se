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