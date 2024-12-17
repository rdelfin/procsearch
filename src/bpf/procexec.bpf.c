// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "procexec.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Dummy instance to get skeleton to generate definition for `struct event`
struct exec_event _exec_event = {0};

// Kernel 5.14 changed the state field to __state
struct task_struct___pre_5_14 {
	long int state;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 20 * sizeof(struct exec_event));
} rb SEC(".maps");

// format:
//        field:unsigned short common_type;       offset:0;       size:2; signed:0;
//        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//        field:int common_pid;   offset:4;       size:4; signed:1;
// 
//        field:int __syscall_nr; offset:8;       size:4; signed:1;
//        field:const char * filename;    offset:16;      size:8; signed:0;
//        field:const char *const * argv; offset:24;      size:8; signed:0;
//        field:const char *const * envp; offset:32;      size:8; signed:0;
struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tp/syscalls/sys_enter_execve")
int handle__syscall_enter_execve(struct execve_args *ctx)
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
  
  // Read process name first
  bpf_probe_read_str(&event->task, sizeof(event->task), (void*)ctx->filename);

  for (size_t i = 0; i < NUM_ARGS; i++) {
    char* arg = NULL;
    bpf_probe_read(&arg, sizeof(arg), &ctx->argv[i]);
    if (arg == NULL) {
      break;
    }
    bpf_probe_read_str(&event->args[i], sizeof(event->args[i]), arg);
  }
  // Submit the reserved data
  bpf_ringbuf_submit(event, 0);
}
