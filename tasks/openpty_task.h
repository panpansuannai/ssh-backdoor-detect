#pragma once
#include <log4cplus/logger.h>

#include "../bpf_task.h"

struct openpty_event_t {
  int pid;
  char comm[16];
  int cpu;
  int action;
  char authtok[125];
  char user[125];
};

BPFTask<openpty_event_t>* get_openpty_task(log4cplus::Logger&);
