#include "pam_task.h"

#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>

#include <string>
#include <thread>
#include <vector>
#include <unordered_map>
#include <cctype>

#include "../bpf_task.h"
#include "../path.h"

static std::string BPF = R"(
#include <uapi/linux/ptrace.h>
typedef struct {
  int pid;
  char comm[16];
  int cpu;
  int pam_func;
  char service_name[16]; // pam_start:0
  int item_type; // pam_get_item pam_set_item
  char item[16]; // pam_get_item pam_set_item
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

int bpf_pam_open_session(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_OPEN_SESSION;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_close_session(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_CLOSE_SESSION;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_vprompt(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_VPROMPT;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_get_item(struct pt_regs *ctx, pam_handle_t* phandle, int item_type, const void** item) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_GET_ITEM;
      event.item_type = item_type;
      bpf_probe_read_user(event.item, 16, *item);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_set_item(struct pt_regs *ctx, pam_handle_t* phandle, int item_type, const void* item) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_SET_ITEM;
      event.item_type = item_type;
      bpf_probe_read(event.item, 16, item);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_setcred(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_SETCRED;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_start(struct pt_regs *ctx, char* service_name, char* user) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_START;
      bpf_probe_read_str(event.service_name, 16, service_name);
      bpf_probe_read_str(event.user, 64, user);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_acct_mgmt(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_ACCT_MGMT;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_get_user(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_GET_USER;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_end(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_END;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int bpf_pam_authenticate(struct pt_regs *ctx, pam_handle_t* phandle) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_AUTHENTICATE;
      bpf_probe_read_str(event.user, 64, phandle->user);
      bpf_probe_read_str(event.authtok, 64, phandle->authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}


int bpf_pam_get_authtok(struct pt_regs *ctx, pam_handle_t* phandle, int item, const char** authtok) {
    pam_event_t event = {};
    if (bpf_get_current_comm(&event.comm, sizeof(event.comm)) == 0) {
      event.pam_func = PAM_GET_AUTHTOK;
      bpf_probe_read_str(event.authtok, 64, *authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
)";

static std::vector<std::shared_ptr<pam_func_handler>> handlers {
  std::make_shared<pam_open_session_handler>(),
  std::make_shared<pam_close_session_handler>(),
  std::make_shared<pam_get_authtok_handler>(),
  std::make_shared<pam_authenticate_handler>(),
  std::make_shared<pam_start_handler>(),
  std::make_shared<pam_end_handler>(),
  std::make_shared<pam_get_user_handler>(),
  std::make_shared<pam_acct_mgmt_handler>(),
  std::make_shared<pam_get_item_handler>(),
  std::make_shared<pam_set_item_handler>(),
  std::make_shared<pam_setcred_handler>(),
  std::make_shared<pam_vprompt_handler>(),
};

// static std::vector<std::string> handlers {
//       "PAM_OPEN_SESSION", "PAM_CLOSE_SESSION", "PAM_GET_AUTHTOK",
//       "PAM_AUTHENTICATE", "PAM_START",         "PAM_END",
//       "PAM_GET_USER",     "PAM_ACCT_MGMT",     "PAM_GET_ITEM",
//       "PAM_SETCRED", "PAM_VPROMPT"
//   };

static std::unordered_map<int, std::shared_ptr<pam_func_handler>>  pam_func_handlers;

static void init_pam_func_handlers() {
  int id = 0;
  for(auto h : handlers) {
    pam_func_handlers[id++] = h;
  }
}

static void replace_bpf_program() {
  for (auto p : pam_func_handlers) {
    int pos;
    auto name = p.second->variable_name();
    if((pos = BPF.find(name)) != std::string::npos) {
      BPF.replace(pos, name.size(), std::to_string(p.first));
    }
  }
}


static void callback(void* cb_cookie, void* data, int size) {
  pam_event_t* event = static_cast<pam_event_t*>(data);
  log4cplus::Logger logger = log4cplus::Logger::getInstance("default");
  if (pam_func_handlers.count(event->pam_func) == 0) {
    return;
  }
  pam_func_handlers[event->pam_func]->handle(event);
}

BPFTask<pam_event_t>* get_pam_task() {
  init_pam_func_handlers();
  replace_bpf_program();

  log4cplus::Logger logger = log4cplus::Logger::getInstance("default");
  BPFTask<pam_event_t>* e = new BPFTask<pam_event_t>(BPF, "events", callback);
  for (auto h : pam_func_handlers) {
    auto func = h.second->get_name();
    auto ret =
        e->attach_uprobe(PATH_PAM, func, "bpf_" + func, 0, h.second->attach_type);
    if (ret.code() != 0) {
      delete e;
    LOG4CPLUS_ERROR_FMT(logger, "pam_task attach_uprobe error: %s", ret.msg().c_str());
      return nullptr;
    }
  }
  return e;
}
