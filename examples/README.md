# Organization

* `crab` - load balancer from the [CRAB project](https://github.com/epfl-dcsl/crab).
* `fw` - firewall from the [hXDP project](https://github.com/axbryd/hXDP-Artifacts).
* `katran` - load balancer from Facebook. ([source](https://github.com/facebookincubator/katran)).
* `headers, common, usr-helpers` - helper code used by XDP programs. Taken from the [XDP project](https://github.com/xdp-project/xdp-tutorial)
* `libbpf-stubbed` - symbolic models for the Linux kernel's `libbpf` API.


# Extracting python performance interfaces

To extract a performance interface for any of the 3 NFs, run `make perf-interface` from within the corresponding directory. 
This should produce a set of files named `res-tree-*.py` where `*` refers to the value of the performance resolution.
