#pragma once

#include <bcc/libbpf.h>
#include "base_handler.h"

class pam_start_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_start";
  }
  void handle(pam_event_t* event) final override {
    LOG4CPLUS_INFO_FMT(logger, "[%s] service_name(%s) user(%s)", attach_func_name().c_str(), event->service_name, event->user);
  }

  pam_start_handler_entry(): pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_start_handler_entry() {};
};

class pam_start_handler_return: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_start";
  }
  void handle(pam_event_t* event) final override {
    LOG4CPLUS_INFO_FMT(logger, "[%s] service_name(%s) user(%s)", attach_func_name().c_str(), event->service_name, event->user);
  }

  pam_start_handler_return(): pam_func_handler(BPF_PROBE_RETURN) {}
  virtual ~pam_start_handler_return() {};
};

class pam_end_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_end";
  }
  pam_end_handler_entry(): pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_end_handler_entry() {};
};

class pam_get_user_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_get_user";
  }
  pam_get_user_handler_entry(): pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_get_user_handler_entry() {};
};

class pam_get_item_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
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
        return;
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
    LOG4CPLUS_INFO_FMT(logger, "[%s] item_type(%s) item(%s) -> %d", attach_func_name().c_str(), item_type.c_str(), event->item, event->ret);
  };

  pam_get_item_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY){}
  virtual ~pam_get_item_handler_entry() {};
};

class pam_set_item_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
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
    LOG4CPLUS_INFO_FMT(logger, "[%s] item_type(%s) item(%s) -> %d", attach_func_name().c_str(), item_type.c_str(), event->item, event->ret);
  };

  pam_set_item_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY){}
  virtual ~pam_set_item_handler_entry() {};
};

class pam_vprompt_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_vprompt";
  }
  pam_vprompt_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY){}
  virtual ~pam_vprompt_handler_entry() {};
};

