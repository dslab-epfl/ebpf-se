/* SPDX-License-Identifier: GPL-2.0 */
#include "stdlib.h"

struct katran_pkt {
  char payload[500];
};

int does_nothing(int nothing) {
  nothing++;
  return nothing;
}

void get_packet2(int type){
  if(type == 0 || type == 3){
    // void* pkt = (void*)0xDEADBEEF;
    void* pkt =   malloc(500);
    // get_packet2(type);
    // does_nothing(type);
  }
}

int main(int argc, char** argv){
  get_packet2(1);
}

// char _license[] SEC("license") = "GPL";