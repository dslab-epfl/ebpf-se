/* Driver for klee verification */
#include "klee/klee.h"
#include <stdlib.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_REDIRECT_MAP
#define USES_BPF_REDIRECT_MAP
#endif

#include "xdp_fw_kern.h"

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

int main(int argc, char** argv){
  BPF_MAP_INIT(&tx_port, "tx_devices_map", "", "tx_device");
  BPF_MAP_INIT(&flow_ctx_table, "flowtable", "pkt.flow", "output_port");

  /* Init from xdp_fw_user.c */
  #define num_ports 2
  int key[num_ports] = {B_PORT,A_PORT};
	int ifindex_out[num_ports] = {B_PORT,A_PORT};

  for(uint i = 0; i < num_ports; i++){
    if(bpf_map_update_elem(&tx_port,&key[i], &ifindex_out[i],0) < 0)
      return -1;
  }
  /* Init done */


  struct pkt *pkt = malloc(sizeof(struct pkt));
  klee_make_symbolic(pkt, sizeof(struct pkt), "user_buf");
  pkt->ether.h_proto = bpf_htons(ETH_P_IP);
  pkt->ipv4.version = 4;
  pkt->ipv4.ihl = sizeof(struct iphdr) / 4;
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  __u32 temp;
  klee_make_symbolic(&(temp), sizeof(temp), "VIGOR_DEVICE");
  test.ingress_ifindex = temp;
  test.rx_queue_index = 0;
  
  bpf_begin();
  if (xdp_fw_prog(&test))
    return 1;
  return 0;
}
