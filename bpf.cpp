#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <chrono>

//#include "bcc_version.h"
#include <bcc/BPF.h>

const std::string BPF_PROGRAM = R"(
#include <uapi/linux/ptrace.h>

struct event_t {
  int pid;
  char comm[16];
  int cpu;
  int action;
  char authtok[125];
  char user[125];
};

BPF_HASH(infotmp, u64, struct event_t);
BPF_PERF_OUTPUT(events);

typedef struct pam_handle
{
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt; /* for use by pam_get_user() */
  char *service_name;
  char *user;
  char *rhost;
  char *ruser;
  char *tty;
  char *xdisplay;
  char *authtok_type; /* PAM_AUTHTOK_TYPE */
  void *data;
  void *env; /* structure to maintain environment list */
} pam_handle_t;

int after_pam_get_authtok(struct pt_regs *ctx) {
    pam_handle_t* phandle = (pam_handle_t*)PT_REGS_PARM1(ctx);

    struct event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      event.action = 1;
      bpf_probe_read_str(event.authtok, 125, phandle->authtok);
      bpf_probe_read_str(event.user, 125, phandle->user);
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

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

std::unordered_map<int, std::chrono::time_point<std::chrono::system_clock>> auth_times;

void process_auth(int pid) {
  auth_times.insert(std::pair<int, std::chrono::time_point<std::chrono::system_clock>>(pid, std::chrono::system_clock::now()));
}

bool check_openpty(int pid) {
  if (auth_times.count(pid) == 0) {
    return false;
  }
  auto auth_time = auth_times[pid];
  auto after_last_auth = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch() - auth_time.time_since_epoch());
  if (after_last_auth.count() >= 10) {
    return false;
  }
  return true;
}

struct event_t {
  int pid;
  char comm[16];
  int cpu; 
  int action;
  char authtok[125];
  char user[125];
};

void event_handler(void* cb_cookie, void* data, int data_size) {
  bool warn = false;
  auto event = static_cast<event_t*>(data);
  std::cout << "{" << std::endl;
  std::cout << "\tPID: " << event->pid << std::endl;
  std::cout << "\tCOMM: " << event->comm << std::endl;
  std::cout << "\tCPU: " << event->cpu << std::endl;
  if (event->action == 0) {
    // openpty
    std::cout << "\tACTION: openpty" << std::endl;
    if (!check_openpty(event->pid)) {
      warn = true;
    }
  } else {
    std::cout << "\tACTION: auth" << std::endl;
    std::cout << "\tUSER: " << event->user << std::endl;
    std::cout << "\tAUTHTOK: " << event->authtok << std::endl;
    process_auth(event->pid);
  }
  std::cout << "}" << std::endl << std::endl;
  if (warn) {
    std::cout << "[WARN]!!: detect unauth openpty" << std::endl;
  }
}

int main() {
  ebpf::BPF bpf;
  auto init_res = bpf.init(BPF_PROGRAM);
  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }


  //std::string fnname = bpf.get_syscall_fnname("openat");
  // std::cout << "attach at " << fnname << std::endl;

  // auto attach_res = bpf.attach_kprobe("do_sys_open", "on_sys_openat");
  // if (attach_res.code() != 0) {
  //   std::cerr << attach_res.msg() << std::endl;
  //   return 1;
  // }

  // attach_res = bpf.attach_kprobe("do_sys_open", "return_sys_openat", 0, BPF_PROBE_RETURN);
  // if (attach_res.code() != 0) {
  //   std::cerr << attach_res.msg() << std::endl;
  //   return 1;
  // }

  std::cout << "Start: " << std::endl;

  auto attach_res = bpf.attach_uprobe("/lib/x86_64-linux-gnu/libpam.so.0", "pam_get_authtok", "after_pam_get_authtok", 0, BPF_PROBE_RETURN);
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  attach_res = bpf.attach_uprobe("/usr/lib/x86_64-linux-gnu/libutil.so", "openpty", "after_openpty", 0, BPF_PROBE_RETURN);
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  bpf.open_perf_buffer("events", event_handler, nullptr, nullptr, 128);

  while(true) {
    bpf.poll_perf_buffer("events");
  }
  return 0;
}