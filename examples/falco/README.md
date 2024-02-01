`falco` is a security monitoring tool.

BPF hooks used:
- tp_btf/sys_enter
- tp_btf/sys_exit
- tp_btf/page_fault_kernel
- tp_btf/page_fault_user
- tp_btf/sched_process_exec
- tp_btf/sched_process_exit
- tp_btf/sched_process_fork
- tp_btf/sched_switch
- tp_btf/signal_deliver

To symbex:

For the attached programs:
```bash
make [filename]_target
make [filename]_symbex

# Example
make sched_switch_target
make sched_switch_symbex
```
For the full list of targets, please refer to [Makefile](Makefile).

For the tail-called syscall programs:
```bash
make sys_target NAME=[syscall name] PROG=[program name-usually ENTER or EXIT]
make sys_symbex NAME=[syscall name]
# Example
make sys_target NAME=accept PROG=ENTER
make sys_symbex NAME=accept
```
