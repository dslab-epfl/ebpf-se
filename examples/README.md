# Organization

**XDP programs:**
* `crab` - load balancer from the [CRAB project](https://github.com/epfl-dcsl/crab).
* `fw` - firewall from the [hXDP project](https://github.com/axbryd/hXDP-Artifacts).
* `katran` - load balancer from Facebook. ([source](https://github.com/facebookincubator/katran)).
* `fluvia` - IPFIX Exporter from the [Fluvia project](https://github.com/nttcom/fluvia/).
* `hercules` - High speed bulk data transfer application from Network Security Group at ETH Zürich. ([source](https://github.com/netsec-ethz/hercules/))

**Non-XDP eBPF programs:**
* `dae` - proxy from the [daeuniverse project](https://github.com/daeuniverse/dae).
* `falco` - kernel monitoring agent from the [Falco project](https://github.com/falcosecurity/libs/).

**Other:**
* `headers, common, usr-helpers` - helper code used by XDP programs. Taken from the [XDP project](https://github.com/xdp-project/xdp-tutorial)

# Analyzing an example

To symbolically execute any of the XDP examples, run `make xdp-target; make symbex` from within the corresponding directory. 
Make sure you have run `make libbpf` once before.
Each of the non-xdp examples contain several subprograms within them. To symbex any of these subprograms, please refer to the corresponding README.
WARNING: The non-XDP programs are still work in progress. 

# Analyzing your own example

We recommend following the existing directory structure and adding your program as a separate folder in this directory. 
The build system is identical to libbpf's so once you have your program, you only need to add a Makefile within your directory that defines the variables `XDP_TARGETS` and `XDP_FUNCTION`. See one of the existing directories for an example.

To modify your program to make it amenable to symbex, you need to perform three steps:
* Declare the BPF helpers your code uses (if this is done incorrectly, your code will not compile)
* Initialize the BPF maps using the BPF_MAP_INIT macro (if this is done incorrectly, your maps will not be symbolic but instead will be zero initialized)
* Initialize your symbolic input (this is identical to how it works in KLEE).

We recommend reading through the code for the `crab` loadbalancer in `crab/lb_kern.c`. Each of these steps are explained using comments.
