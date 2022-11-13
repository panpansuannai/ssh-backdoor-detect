#pragma once

#include "../bpf_task.h"

typedef struct {
  int pid;
  char comm[16];
  int cpu;
  char pam_func[64];
  char user[64];
  char authtok[64];
} pam_event_t; 

BPFTask<pam_event_t>* get_pam_task();