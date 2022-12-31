#pragma once

#include "base_handler.h"

class pam_acct_mgmt_handler_entry: public pam_func_handler {
public:
  std::string attach_func_name() final override {
    return "pam_acct_mgmt";
  }

  pam_acct_mgmt_handler_entry() : pam_func_handler(BPF_PROBE_ENTRY) {}
  virtual ~pam_acct_mgmt_handler_entry() {};
};

