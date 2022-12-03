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
  char comm[16];
  int cpu;
  int pam_func;
  char service_name[16]; // pam_start:0
  int item_type; // pam_get_item:1 pam_set_item:1
  char item[16]; // pam_get_item:2 pam_set_item:2
  char user[64];
  char authtok[64];
} pam_event_t;

BPFTask<pam_event_t>* get_pam_task();

static std::string uppercase(std::string& s) {
  std::string ret = s;
  for (int i = 0; i < ret.size(); i++) {
    ret[i] = std::toupper(ret[i]);
  }
  return ret;
}

class pam_func_handler {
public:
  virtual std::string get_name() = 0;
  virtual void handle(pam_event_t*) {
    LOG4CPLUS_INFO_FMT(logger, "[%s]", get_name().c_str());
  };

  std::string variable_name() {
    auto name = get_name();
    return uppercase(name);
  }

  pam_func_handler(bpf_probe_attach_type t = BPF_PROBE_RETURN) : attach_type(t) {
    logger = log4cplus::Logger::getInstance("default");
  };
  virtual ~pam_func_handler(){};

  bpf_probe_attach_type attach_type;
  log4cplus::Logger logger;
};


class pam_open_session_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_open_session";
  }
  virtual ~pam_open_session_handler() {};
};

class pam_close_session_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_close_session";
  }
  virtual ~pam_close_session_handler() {};
};

class pam_get_authtok_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_get_authtok";
  }

  void handle(pam_event_t* event) final override {
    LOG4CPLUS_INFO_FMT(logger, "[%s] authtok(%s)", get_name().c_str(), event->authtok);
  }
  virtual ~pam_get_authtok_handler() {};
};

class pam_authenticate_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_authenticate";
  }
  virtual ~pam_authenticate_handler() {};
};

class pam_start_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_start";
  }
  void handle(pam_event_t* event) final override {
    LOG4CPLUS_INFO_FMT(logger, "[%s] service_name(%s) user(%s)", get_name().c_str(), event->service_name, event->user);
  }

  pam_start_handler(): pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_start_handler() {};
};

class pam_end_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_end";
  }
  virtual ~pam_end_handler() {};
};

class pam_get_user_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_get_user";
  }
  virtual ~pam_get_user_handler() {};
};

class pam_acct_mgmt_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_acct_mgmt";
  }
  virtual ~pam_acct_mgmt_handler() {};
};

class pam_get_item_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_get_item";
  }

  void handle(pam_event_t* event) final override {
    std::string item_type = "";
    switch(event->item_type) {
      case PAM_SERVICE: 
        item_type = "PAM_SERVICE";
        break;
      case PAM_USER:
        item_type = "PAM_USER";
        break;
      case PAM_USER_PROMPT:
        item_type = "PAM_USER_PROMPT";
        break;
      case PAM_TTY:
        item_type = "PAM_TTY";
        break;
      case PAM_RUSER:
        item_type = "PAM_RUSER";
        break;
      case PAM_RHOST:
        item_type = "PAM_RHOST";
        break;
      case PAM_AUTHTOK:
        item_type = "PAM_AUTHTOK";
        break;
      case PAM_CONV:
        item_type = "PAM_CONV";
        break;
      case PAM_FAIL_DELAY:
        item_type = "PAM_FAIL_DELAY";
        break;
      case PAM_XDISPLAY:
        item_type = "PAM_XDISPLAY";
        break;
      case PAM_XAUTHDATA:
        item_type = "PAM_XAUTHDATA";
        break;
      case PAM_AUTHTOK_TYPE:
        item_type = "PAM_AUTHTOK_TYPE";
        break;
    }
    LOG4CPLUS_INFO_FMT(logger, "[%s] item_type(%s) item(%s)", get_name().c_str(), item_type.c_str(), event->item);
  };

  pam_get_item_handler() : pam_func_handler(BPF_PROBE_RETURN){}
  virtual ~pam_get_item_handler() {};
};

class pam_set_item_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_set_item";
  }

  void handle(pam_event_t* event) final override {
    std::string item_type = "";
    switch(event->item_type) {
      case PAM_SERVICE: 
        item_type = "PAM_SERVICE";
        break;
      case PAM_USER:
        item_type = "PAM_USER";
        break;
      case PAM_USER_PROMPT:
        item_type = "PAM_USER_PROMPT";
        break;
      case PAM_TTY:
        item_type = "PAM_TTY";
        break;
      case PAM_RUSER:
        item_type = "PAM_RUSER";
        break;
      case PAM_RHOST:
        item_type = "PAM_RHOST";
        break;
      case PAM_AUTHTOK:
        item_type = "PAM_AUTHTOK";
        break;
      case PAM_CONV:
        item_type = "PAM_CONV";
        break;
      case PAM_FAIL_DELAY:
        item_type = "PAM_FAIL_DELAY";
        break;
      case PAM_XDISPLAY:
        item_type = "PAM_XDISPLAY";
        break;
      case PAM_XAUTHDATA:
        item_type = "PAM_XAUTHDATA";
        break;
      case PAM_AUTHTOK_TYPE:
        item_type = "PAM_AUTHTOK_TYPE";
        break;
    }
    LOG4CPLUS_INFO_FMT(logger, "[%s] item_type(%s) item(%s)", get_name().c_str(), item_type.c_str(), event->item);
  };

  pam_set_item_handler() : pam_func_handler(BPF_PROBE_ENTRY){}
  virtual ~pam_set_item_handler() {};
};

class pam_setcred_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_setcred";
  }
  virtual ~pam_setcred_handler() {};
};

class pam_vprompt_handler: public pam_func_handler {
public:
  std::string get_name() final override {
    return "pam_vprompt";
  }
  virtual ~pam_vprompt_handler() {};
};

