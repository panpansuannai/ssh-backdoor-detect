#include "openpty_task.h"

#include <string>
#include <iostream>

#include "../bpf_task.h"
#include "../path.h"

static const std::string BPF = R"(
#include <uapi/linux/ptrace.h>

struct event_t {
  int pid;
  char comm[16];
  int cpu;
  int action;
  char authtok[125];
  char user[125];
};

BPF_PERF_OUTPUT(events);

int after_openpty(struct pt_regs* ctx) {
  struct event_t event = {};
  if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
    u64 id = bpf_get_current_pid_tgid();
    event.pid = id >>  32;
    event.cpu = bpf_get_smp_processor_id();
    event.action = 0;
    events.perf_submit(ctx, &event, sizeof(event));
  }
  return 0;
}
)";

BPFTask<openpty_event_t>* get_openpty_task() {
    auto t = new BPFTask<openpty_event_t>(BPF, "events", [](void* cb_cookie, void* data, int size){
      std::cout << "OPENPTY();" << std::endl;
    });
    auto attach_ret = t->attach_uprobe(PATH_UTIL, "openpty", "after_openpty", 0, BPF_PROBE_RETURN);
    if (attach_ret.code() != 0) {
      delete t;
      return nullptr;
    }
    return t;
}