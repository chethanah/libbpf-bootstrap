/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Reference: https://github.com/libbpf/libbpf-bootstrap*/

#include <argp.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "memtest.skel.h"

static volatile bool exiting = false;

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct memtest_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = memtest_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	// skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = memtest_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = memtest_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Running memtest...");
	while (!exiting) {
		/* trigger our BPF program */
		sleep(1);
	}

cleanup:
	/* Clean up */
	memtest_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

