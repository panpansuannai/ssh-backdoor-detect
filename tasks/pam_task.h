#pragma once
#include <bcc/BPF.h>

#include <bcc/libbpf.h>
#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>
#include <security/_pam_types.h>
#include <security/pam_modules.h>

#include <string>

#include "../bpf_task.h"

typedef struct {
  int pid;
  int cpu;
  int pam_func;
  int ret;
  int item_type; // pam_get_item:1 pam_set_item:1
  char comm[16];
  char service_name[16]; // pam_start:0
  char user[16]; // pam_start:1
  char item[16]; // pam_get_item:2 pam_set_item:2
} pam_event_t;

BPFTask<pam_event_t>* get_pam_task();
