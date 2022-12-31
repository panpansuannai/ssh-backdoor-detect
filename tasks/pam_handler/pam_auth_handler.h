#pragma once

#include "base_handler.h"

class pam_get_authtok_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_get_authtok";
  }

  void handle(pam_event_t* event) final override {
    LOG4CPLUS_INFO_FMT(logger, "[%s] authtok(%s)", attach_func_name().c_str(), event->item);
  }

  pam_get_authtok_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_get_authtok_handler_entry() {};
};

class pam_authenticate_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_authenticate";
  }
  
  pam_authenticate_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_authenticate_handler_entry() {};
};

class pam_authenticate_handler_return: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_authenticate";
  }
  
  pam_authenticate_handler_return() : pam_func_handler(BPF_PROBE_RETURN) {}
  virtual ~pam_authenticate_handler_return() {};
};
