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
#include "pam_handler/pam_acct_handler.h"
#include "pam_handler/pam_auth_handler.h"
#include "pam_handler/pam_misc_handler.h"
#include "pam_handler/pam_session_handler.h"

static std::string BPF = R"(
#include <uapi/linux/ptrace.h>

#define PAM_SERVICE	   1	/* The service name */
#define PAM_USER           2	/* The user name */
#define PAM_TTY            3	/* The tty name */
#define PAM_RHOST          4	/* The remote host name */
#define PAM_CONV           5	/* The pam_conv structure */
#define PAM_AUTHTOK        6	/* The authentication token (password) */
#define PAM_OLDAUTHTOK     7	/* The old authentication token */
#define PAM_RUSER          8	/* The remote user name */
#define PAM_USER_PROMPT    9    /* the prompt for getting a username */
/* Linux-PAM extensions */
#define PAM_FAIL_DELAY     10   /* app supplied function to override failure
				   delays */
#define PAM_XDISPLAY       11   /* X display name */
#define PAM_XAUTHDATA      12   /* X server authentication data */
#define PAM_AUTHTOK_TYPE   13   /* The type for pam_get_authtok */

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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
      event.item_type = item_type;
      if (item_type == PAM_SERVICE) {
        bpf_probe_read_str(event.item, 16, phandle->service_name);
      } else if (item_type == PAM_USER) {
        bpf_probe_read_str(event.item, 16, phandle->user);
      } else if (item_type == PAM_TTY) {
        bpf_probe_read_str(event.item, 16, phandle->tty);
      } else if (item_type == PAM_RHOST) {
        bpf_probe_read_str(event.item, 16, phandle->rhost);
      } else if (item_type == PAM_AUTHTOK) {
        bpf_probe_read_str(event.item, 16, phandle->authtok);
      } else if (item_type == PAM_OLDAUTHTOK) {
        bpf_probe_read_str(event.item, 16, phandle->oldauthtok);
      } else if (item_type == PAM_RUSER) {
        bpf_probe_read_str(event.item, 16, phandle->ruser);
      } else if (item_type == PAM_USER_PROMPT) {
        bpf_probe_read_str(event.item, 16, phandle->prompt);
      }
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
      bpf_probe_read(event.service_name, 16, service_name);
      bpf_probe_read(event.user, 16, user);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
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
      event.ret = PT_REGS_RC(ctx);
      bpf_probe_read_str(event.item, 16, *authtok);
      u64 id = bpf_get_current_pid_tgid();
      event.pid = id >>  32;
      event.cpu = bpf_get_smp_processor_id();
      events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
)";

static std::vector<std::shared_ptr<pam_func_handler>> handlers {
  std::make_shared<pam_start_handler_return>(),
  std::make_shared<pam_end_handler_entry>(),
  std::make_shared<pam_open_session_handler_entry>(),
  std::make_shared<pam_close_session_handler_entry>(),
  std::make_shared<pam_get_authtok_handler_entry>(),
  std::make_shared<pam_authenticate_handler_entry>(),
  std::make_shared<pam_authenticate_handler_return>(),
  std::make_shared<pam_get_user_handler_entry>(),
  std::make_shared<pam_acct_mgmt_handler_entry>(),
  std::make_shared<pam_get_item_handler_entry>(),
  std::make_shared<pam_set_item_handler_entry>(),
  std::make_shared<pam_setcred_handler_entry>(),
  std::make_shared<pam_vprompt_handler_entry>(),
};


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
    auto name = p.second->attach_func_type_variable();
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
    auto func = h.second->attach_func_name();
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
