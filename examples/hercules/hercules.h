// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __HERCULES_H__
#define __HERCULES_H__

#include <stdbool.h>
#include <stdatomic.h>
#include <linux/types.h>

#define MAX_NUM_SOCKETS 256
#define HERCULES_MAX_HEADERLEN 256

struct hercules_path_header {
	const char header[HERCULES_MAX_HEADERLEN]; //!< headerlen bytes
	__u16 checksum;    //SCION L4 checksum over header with 0 payload
};

struct hercules_session;

// Path are specified as ETH/IP/UDP/SCION/UDP headers.
struct hercules_path {
	__u64 next_handshake_at;
	int headerlen;
	int payloadlen;
	int framelen;    //!< length of ethernet frame; headerlen + payloadlen
	int ifid;
	struct hercules_path_header header;
	atomic_bool enabled; // e.g. when a path has been revoked and no replacement is available, this will be set to false
	atomic_bool replaced;
};

// Connection information
struct hercules_app_addr {
	/** SCION IA. In network byte order. */
	__u64 ia;
	/** SCION IP. In network byte order. */
	__u32 ip;
	/** SCION/UDP port (L4, application). In network byte order. */
	__u16 port;
};

typedef __u64 ia;


struct hercules_session *hercules_init(int *ifindices, int num_ifaces, struct hercules_app_addr local_addr, int queue, int mtu);
void hercules_close(struct hercules_session *session);

struct path_stats_path {
    __u64 total_packets;
    __u64 pps_target;
};

struct path_stats {
    __u32 num_paths;
    struct path_stats_path paths[1]; // XXX this is actually used as a dynamic struct member; the 1 is needed for CGO
};
struct path_stats *make_path_stats_buffer(int num_paths);

struct hercules_stats {
	__u64 start_time;
	__u64 end_time;
	__u64 now;

	__u64 tx_npkts;
	__u64 rx_npkts;

	__u64 filesize;
	__u32 framelen;
	__u32 chunklen;
	__u32 total_chunks;
	__u32 completed_chunks; //!< either number of acked (for sender) or received (for receiver) chunks

	__u32 rate_limit;
};

// Get the current stats of a running transfer.
// Returns stats with `start_time==0` if no transfer is active.
struct hercules_stats hercules_get_stats(struct hercules_session *session, struct path_stats* path_stats);

void allocate_path_headers(struct hercules_session *session, struct hercules_path *path, int num_headers);
void push_hercules_tx_paths(struct hercules_session *session);

// locks for working with the shared path memory
void acquire_path_lock(void);
void free_path_lock(void);

// Initiate transfer of file over the given path.
// Synchronous; returns when the transfer has been completed or if it has failed.
// Does not take ownership of `paths`.
struct hercules_stats
hercules_tx(struct hercules_session *session, const char *filename, int offset, int length,
            const struct hercules_app_addr *destinations, struct hercules_path *paths_per_dest, int num_dests,
            const int *num_paths, int max_paths, int max_rate_limit, bool enable_pcc, int xdp_mode, int num_threads);

// Initiate receiver, waiting for a transmitter to initiate the file transfer.
struct hercules_stats hercules_rx(struct hercules_session *session, const char *filename, int xdp_mode,
                                  bool configure_queues, int accept_timeout, int num_threads, bool is_pcc_benchmark);

#endif // __HERCULES_H__
