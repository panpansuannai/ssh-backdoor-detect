#pragma once

#include "base_handler.h"

class pam_open_session_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_open_session";
  }
  pam_open_session_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY){};
  virtual ~pam_open_session_handler_entry() {};
};

class pam_close_session_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_close_session";
  }
  pam_close_session_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY){};
  virtual ~pam_close_session_handler_entry() {};
};


class pam_setcred_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_setcred";
  }
  pam_setcred_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY){};
  virtual ~pam_setcred_handler_entry() {};
};

