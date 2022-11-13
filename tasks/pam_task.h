#pragma once

#include "../bpf_task.h"

typedef struct {
  int pid;
  char comm[16];
  int cpu;
  char authtok[20];
  char user[20];
} pam_event_t; 

BPFTask<pam_event_t>* get_pam_task();