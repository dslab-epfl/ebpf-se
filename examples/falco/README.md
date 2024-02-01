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
```
make [filename]_target
make [filename]_symbex
// example
make sched_switch_target
make sched_switch_symbex
```
For the tail-called syscall programs:
```
make sys_target NAME=[syscall name] PROG=[program name-usually ENTER or EXIT]
make sys_symbex NAME=[syscall name]
```
