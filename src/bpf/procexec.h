/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCEXEC_H
#define __PROCEXEC_H

#define TASK_COMM_LEN 256
#define ARG_LEN 256
#define NUM_ARGS 16

struct exec_event {
  pid_t pid;
	u8 task[TASK_COMM_LEN];
	u8 args[NUM_ARGS][ARG_LEN];
};

#endif /* __PROCEXEC_H */
