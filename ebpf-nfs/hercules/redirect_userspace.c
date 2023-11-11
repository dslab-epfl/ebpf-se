// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2017 - 2018 Intel Corporation.
// Copyright(c) 2019 ETH Zurich.

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_REDIRECT_MAP
#define USES_BPF_REDIRECT_MAP
#endif

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include "../common/debug_tags.h"
#endif

#include <linux/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include "packet.h"
#include "hercules.h"

#include <bpf/bpf_helpers.h>


struct bpf_map_def SEC("maps") xsks_map = {
		.type        = BPF_MAP_TYPE_XSKMAP,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u32),
		.max_entries = MAX_NUM_SOCKETS,
};

struct bpf_map_def SEC("maps") num_xsks = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u32),
		.max_entries = 1,
};

struct bpf_map_def SEC("maps") local_addr = {
		.type        = BPF_MAP_TYPE_ARRAY,
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct hercules_app_addr),
		.max_entries = 1,
};

static int redirect_count = 0;
static __u32 zero = 0;

SEC("xdp")
int xdp_prog_redirect_userspace(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	size_t offset = sizeof(struct ether_header) +
	                sizeof(struct iphdr) +
	                sizeof(struct udphdr) +
	                sizeof(struct scionhdr) +
	                sizeof(struct scionaddrhdr_ipv4) +
	                sizeof(struct udphdr);
	if(data + offset > data_end) {
		VIGOR_TAG(REACHED_STATE, TOO_FEW_HEADERS); // NOT REACHED
		return XDP_PASS; // too short
	}
	const struct ether_header *eh = (const struct ether_header *)data;
	if(eh->ether_type != htons(ETHERTYPE_IP)) {
		VIGOR_TAG(REACHED_STATE, NOT_IP);
		return XDP_PASS; // not IP
	}
	const struct iphdr *iph = (const struct iphdr *)(eh + 1);
	if(iph->protocol != IPPROTO_UDP) {
		VIGOR_TAG(REACHED_STATE, NOT_UDP_1);
		return XDP_PASS; // not UDP
	}

	// get listening address
	struct hercules_app_addr *addr = bpf_map_lookup_elem(&local_addr, &zero);
	if(addr == NULL) {
		VIGOR_TAG(REACHED_STATE, NO_LISTENER_ADDRESS); // NOT REACHED
		return XDP_PASS; // not listening
	}

	// check if IP address matches
	if(iph->daddr != addr->ip) {
		VIGOR_TAG(REACHED_STATE, WRONG_IP);
		return XDP_PASS; // not addressed to us (IP address)
	}

	// check if UDP port matches
	const struct udphdr *udph = (const struct udphdr *)(iph + 1);
	if(udph->uh_dport != htons(SCION_ENDHOST_PORT)) {
		VIGOR_TAG(REACHED_STATE, WRONG_UDP_PORT);
		return XDP_PASS; // not addressed to us (UDP port)
	}

	// parse SCION header
	const struct scionhdr *scionh = (const struct scionhdr *)(udph + 1);
	if(scionh->version != 0u) {
		VIGOR_TAG(REACHED_STATE, UNSUPPORTED_SCION);
		return XDP_PASS; // unsupported SCION version
	}
	if(scionh->dst_type != 0u) {
		VIGOR_TAG(REACHED_STATE, UNSUPPORTED_DST_ADDRESS);
		return XDP_PASS; // unsupported destination address type
	}
	if(scionh->src_type != 0u) {
		VIGOR_TAG(REACHED_STATE, UNSUPPORTED_SRC_ADDRESS);
		return XDP_PASS; // unsupported source address type
	}
	if(scionh->next_header != IPPROTO_UDP) {
		VIGOR_TAG(REACHED_STATE, NOT_UDP);
		return XDP_PASS;
	}

	const struct scionaddrhdr_ipv4 *scionaddrh = (const struct scionaddrhdr_ipv4 *)(scionh + 1);
	if(scionaddrh->dst_ia != addr->ia) {
		VIGOR_TAG(REACHED_STATE, WRONG_SCION_DEST);
		return XDP_PASS; // not addressed to us (IA)
	}
	if(scionaddrh->dst_ip != addr->ip) {
		VIGOR_TAG(REACHED_STATE, WRONG_SCION_DEST2);
		return XDP_PASS; // not addressed to us (IP in SCION hdr)
	}
	offset += scionh->header_len * SCION_HEADER_LINELEN - // Header length is in lineLen of SCION_HEADER_LINELEN bytes
	          sizeof(struct scionhdr) -
	          sizeof(struct scionaddrhdr_ipv4);

	// Finally parse the L4-UDP header
	const struct udphdr *l4udph = ((void *)scionh) + scionh->header_len * SCION_HEADER_LINELEN;
	if((void *)(l4udph + 1) > data_end) {
		VIGOR_TAG(REACHED_STATE, TOO_SHORT); // NOT REACHED
		return XDP_PASS; // too short after all
	}
	if(l4udph->dest != addr->port) {
		VIGOR_TAG(REACHED_STATE, WRONG_UDP_DEST);
		return XDP_PASS;
	}

	// write the payload offset to the first word, so that the user space program can continue from there.
	*(__u32 *)data = offset;

	__u32 *_num_xsks = bpf_map_lookup_elem(&num_xsks, &zero);
	if(_num_xsks == NULL) {
		VIGOR_TAG(REACHED_STATE, NO_NUM_XSK); // NOT REACHED
		return XDP_PASS;
	}
	__sync_fetch_and_add(&redirect_count, 1);

	return bpf_redirect_map(&xsks_map, (redirect_count) % (*_num_xsks),
	                        0); // XXX distribute across multiple sockets, once available
}

/** Symbex driver starts here **/

#ifdef KLEE_VERIFICATION

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  char payload[1500];
};

int main(int argc, char **argv) {
  BPF_MAP_INIT(&xsks_map, "xsks_map", "", "");
	BPF_MAP_INIT(&num_xsks, "num_xsks", "", "");
	BPF_MAP_INIT(&local_addr, "local_addr", "", "");

	__u32 k;
	klee_make_symbolic(&k, sizeof(k), "k");
	
	klee_assume(k > 0);		// constrain num_xsks to have a first element that is non-zero
												// else last line has div by 0
	bpf_map_update_elem(&num_xsks, &zero, &k, BPF_ANY);
  
  struct pkt *pkt = malloc(sizeof(struct pkt));
  klee_make_symbolic(pkt, sizeof(struct pkt), "packet");

  struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;
  test.rx_queue_index = 0;

  bpf_begin();
  if (xdp_prog_redirect_userspace(&test))
    return 1;
  return 0;
}

#endif // KLEE_VERIFICATION

char _license[] SEC("license") = "GPL";