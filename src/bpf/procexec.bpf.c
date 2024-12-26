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

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, pid_t);
  __type(value, struct exec_event);
} exec_inter SEC(".maps");

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
  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = (pid_t)(pid_tgid & 0xFFFFFFFF);

  struct exec_event* event = bpf_map_lookup_elem(&exec_inter, &pid);

  if (event == NULL) {
    struct exec_event new_event;
    int result = bpf_map_update_elem(&exec_inter, &pid, &new_event, BPF_NOEXIST);
    if (result != 0) {
      return 1;
    }
    event = bpf_map_lookup_elem(&exec_inter, &pid);
    if (event == NULL) {
      return 1;
    }
  }

  event->pid = pid;
  // Read process name first
  size_t num_args = 0;
  bpf_probe_read_str(&event->task, sizeof(event->task), (void*)ctx->filename);
  for (num_args = 0; num_args < NUM_ARGS; num_args++) {
    char* arg = NULL;
    bpf_probe_read(&arg, sizeof(arg), &ctx->argv[num_args]);
    if (arg == NULL) {
      break;
    }
    bpf_probe_read_str(&event->args[num_args], sizeof(event->args[num_args]), arg);
  }
  event->num_args = num_args;

  return 0;
}

// name: sched_process_exec
// ID: 323
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
// 
//         field:__data_loc char[] filename;       offset:8;       size:4; signed:0;
//         field:pid_t pid;        offset:12;      size:4; signed:1;
//         field:pid_t old_pid;    offset:16;      size:4; signed:1;
// 
// print fmt: "filename=%s pid=%d old_pid=%d", __get_str(filename), REC->pid, REC->old_pid

struct sched_process_exec_args {
  short common_type;
  char common_flags;
  char common_preempt_count;
  int common_pid;
  char *filename;
  pid_t pid;
  pid_t old_pid;
};

SEC("tp/sched/sched_process_exec")
int handle__sched_process_exec(struct sched_process_exec_args *ctx)
{
  struct exec_event* event = bpf_map_lookup_elem(&exec_inter, &ctx->pid);

  if (!event) {
    // bpf_printk("sched_process_exec did not correspond to a execve call\n");
    return 1;
  }

  struct exec_event* new_event = bpf_ringbuf_reserve(&rb, sizeof(struct exec_event), 0);

  if(!event) {
    // if bpf_ringbuf_reserve fails, print an error message and return
    // bpf_printk("bpf_ringbuf_reserve failed\n");
    return 1;
  }

  bpf_probe_read(new_event, sizeof(struct exec_event), event);
  bpf_ringbuf_submit(event, 0);

  return 0;
}
