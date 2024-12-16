// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "procexec.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;

// Dummy instance to get skeleton to generate definition for `struct event`
struct exec_event _exec_event = {0};

// Kernel 5.14 changed the state field to __state
struct task_struct___pre_5_14 {
	long int state;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle__syscall_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
  struct exec_event* event = bpf_ringbuf_reserve(&rb, sizeof(struct exec_event), 0);
  if(!event) {
    // if bpf_ringbuf_reserve fails, print an error message and return
    bpf_printk("bpf_ringbuf_reserve failed\n");
    return 1;
  }

  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = (pid_t)(pid_tgid & 0xFFFFFFFF);
  event->pid = pid;
  event->task[0] = 'a';
  event->task[1] = 'b';
  event->task[2] = 'c';
  event->task[3] = 0;
  // Submit the reserved data
  bpf_ringbuf_submit(event, 0);
}
