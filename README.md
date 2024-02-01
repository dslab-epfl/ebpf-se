# eBPF-SE

This repository hosts eBPF-SE, a tool that can be used to symbolically execute programs written using the Linux kernel's eBPF framework.
eBPF-SE was previously a part of [PIX](https://github.com/dslab-epfl/pix), a tool that automatically extracts performance interfaces from NF code. 
In case eBPF-SE is useful to you in any published work, please cite the [PIX paper](https://www.usenix.org/conference/nsdi22/presentation/iyer) published at NSDI'22.

# Organization

Subdirectories have their own README files.

* `examples` - contains a set of example eBPF programs that eBPF-SE has been used to symbolically execute so far.
* `tool` - contains the symbolic execution engine which is based on [KLEE](https://github.com/klee/klee)


# Getting Started

First, setup the tool as follows:
```bash
cd tool
./setup-tool.sh
source paths.sh
```

This step should take approximately 10 minutes and will install the symbolic execution along with all of its dependencies ([KLEE](https://github.com/klee/klee), [klee-uclibc](https://github.com/klee/klee-uclibc) and [Z3](https://github.com/Z3Prover/z3)).
This also creates a `paths.sh` file which contains commands to add `klee` and its include directory to your path. We recommend adding `source ebpf-se/tool/paths.sh` to your `.bashrc` for ease of use. 

Then, to test the tool on any of the provided examples (for instance, Katran):
```bash
cd examples/katran  # Replace with example of your choice here
make libbpf-stubbed # This needs to be done only for the first example you run
make xdp-target
make symbex
```

You should automatically see the KLEE output at the end of third step, which describes the total number of paths explored during symbolic execution.
The analysis for Katran, which is one of the more complex eBPF programs, takes approximately 2 minutes and yields 10678 paths.


# Using eBPF-SE to analyze your own eBPF programs

Please follow the steps listed in [examples/README.md](examples/README.md).


# Other information

- All code in this repository was tested on Ubuntu 22.04.
- For any questions, please contact [Rishabh Iyer](mailto:rishabh.iyer@berkeley.edu)
