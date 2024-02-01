
#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_XDP_ADJUST_HEAD
#define USES_BPF_XDP_ADJUST_HEAD
#endif

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifdef GUE_ENCAP
#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif
#endif 

#include "klee/klee.h"
#include <stdlib.h>
#include "pckt_encap_driver_helper.h"

__attribute__((noinline)) int pckt_encap_isolated(struct xdp_md* xdp,
    struct ctl_value* cval,
    bool is_ipv6,
    struct packet_description* pckt,
    struct real_definition* dst,
    __u32 pkt_bytes) {
      if(is_ipv6)
        return gue_encap_v6(xdp, cval, is_ipv6, pckt, dst, pkt_bytes);
      else 
        return gue_encap_v4(xdp, cval, pckt, dst, pkt_bytes);
    }

int main(int argc, char **argv) {

#ifdef GUE_ENCAP
  BPF_MAP_INIT(&pckt_srcs, "srcs_map", "", "vip_metadata");
#endif
  struct xdp_md test;
  bool is_ipv6;
  if(klee_int("pkt.isIPv4")){
      get_packet(IPV4,&test);
      is_ipv6 = false;
  }
  else{
      get_packet(IPV6,&test);
      is_ipv6 = true;
  }

  test.data_meta = 0;
  test.ingress_ifindex = 0;
  test.rx_queue_index = 0;

  struct ctl_value* cval = malloc(sizeof(struct ctl_value));
  cval->value = 1;
  cval->ifindex = 0;
  for (int i = 0; i <6; i ++)
    cval->mac[i] = 42;
  struct packet_description* pkt_des = malloc(sizeof(struct packet_description));
  struct real_definition *dst = malloc(sizeof(struct real_definition));
  memset(pkt_des,0,sizeof(struct packet_description));
  memset(dst,0,sizeof(struct real_definition));

  if (pckt_encap_isolated(&test,cval,is_ipv6,pkt_des,dst,50))
    return 1;
  return 0;
}
