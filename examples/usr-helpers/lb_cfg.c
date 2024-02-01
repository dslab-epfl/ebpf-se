static const char *__doc__ = "LoadBalancer configurator\n";

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/if_ether.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"targets",     required_argument,	NULL, 't' },
	 "Comma separated list of targets ip@mac", "<ip@mac>", true},

	{{0, 0, NULL,  0 }}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif
const char *pin_basedir =  "/sys/fs/bpf";

static inline int str_to_eth_addr(const char *src, unsigned char *dst)
{
	if (sscanf(src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst[0], &dst[1], &dst[2],
			&dst[3], &dst[4], &dst[5]) != 6)
		return -EINVAL;

	return 0;
}

static int parse_target(char *target, int *ip, unsigned char *mac)
{
	char *token, *saveptr;
	struct sockaddr_in sa;

	saveptr = target;
	/* IP */
	token = strtok_r(saveptr, "@", &saveptr);
	inet_pton(AF_INET, token, &(sa.sin_addr));
	*ip = sa.sin_addr.s_addr;

	/* MAC */
	token = strtok_r(saveptr, "@", &saveptr);
	str_to_eth_addr(token, mac);

	return 0;
}

int main(int argc, char **argv)
{
	char pin_dir[PATH_MAX];
	int targets_map_fd, macs_map_fd, target_count_fd;
	int len, target_count, zero = 0;
	int target_ip;
	unsigned char target_mac[ETH_ALEN];
	char *token, *saveptr;

	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (strlen(cfg.targets) == 0) {
		fprintf(stderr, "ERR: required option --targets missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	targets_map_fd = open_bpf_map_file(pin_dir, "targets_map", NULL);
	if (targets_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}
	macs_map_fd = open_bpf_map_file(pin_dir, "macs_map", NULL);
	if (macs_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	target_count_fd = open_bpf_map_file(pin_dir, "targets_count", NULL);
	if (macs_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	saveptr = cfg.targets;
	token = strtok_r(saveptr, ",", &saveptr);
	target_count = 0;
	while(token) {
		parse_target(token, &target_ip, target_mac);
		token = strtok_r(saveptr, ",", &saveptr);

		/* Update targets map */
		if (bpf_map_update_elem(targets_map_fd, &target_count, &target_ip, 0) < 0) {
			fprintf(stderr,
					"WARN: Failed to update bpf map file: err(%d):%s\n",
					errno, strerror(errno));
			return -1;
		}

		/* Update MACs map */
		if (bpf_map_update_elem(macs_map_fd, &target_ip, target_mac, 0) < 0) {
			fprintf(stderr,
					"WARN: Failed to update bpf map file: err(%d):%s\n",
					errno, strerror(errno));
			return -1;
		}

		target_count++;
	}

	/* Update target count map */

	if (bpf_map_update_elem(target_count_fd, &zero, &target_count, 0) < 0) {
		fprintf(stderr,
				"WARN: Failed to update bpf map file: err(%d):%s\n",
				errno, strerror(errno));
		return -1;
	}
	return EXIT_OK;
}
