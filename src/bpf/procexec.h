/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCEXEC_H
#define __PROCEXEC_H

#define TASK_COMM_LEN 256

struct exec_event {
  pid_t pid;
	u8 task[TASK_COMM_LEN];
};

#endif /* __PROCEXEC_H */
