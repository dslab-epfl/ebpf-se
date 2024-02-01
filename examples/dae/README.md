`dae` is a high performance proxy.

BPF hooks used:
- tc/egress
- tc/ingress
- tc/wan_egress
- tc/wan_ingress
- cgroup/sock_create
- cgroup/sock_release
- cgroup/connect4
- cgroup/connect6
- cgroup/sendmsg4
- cgroup/sendmsg6

To symbex:

```bash
make target PROG=[program]
make symbex
```

Symbexed programs:
- CGROUP
- RELEASE

TODO programs:
- INGRESS
- EGRESS
- WAN_INGRESS
- WAN_EGRESS