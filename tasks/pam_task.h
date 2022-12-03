#pragma once

#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>

#include <string>

#include "../bpf_task.h"

typedef struct {
  int pid;
  char comm[16];
  int cpu;
  int pam_func;
  int item_type; // pam_get_item
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

  pam_func_handler() {
    logger = log4cplus::Logger::getInstance("default");
  };
  virtual ~pam_func_handler(){};

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
    LOG4CPLUS_INFO_FMT(logger, "[%s] item_type(%d)", get_name().c_str(), event->item_type);
  };

  virtual ~pam_get_item_handler() {};
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

