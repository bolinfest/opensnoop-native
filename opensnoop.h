/**
 * This header contains definitions that are shared with
 * opensnoop.c and opensnoop.py.
 */

// This seems like it should be in <linux/sched.h>,
// but I don't have it there on Ubuntu 18.04.
#ifndef TASK_COMM_LEN
// Task command name length:
#define TASK_COMM_LEN 16
#endif

#define NAME_MAX 255

struct val_t {
  unsigned long long id;
  char comm[TASK_COMM_LEN];
  const char *fname;
};

struct data_t {
  unsigned long long id;
  unsigned long long ts;
  int ret;
  char comm[TASK_COMM_LEN];
  char fname[NAME_MAX];
};
