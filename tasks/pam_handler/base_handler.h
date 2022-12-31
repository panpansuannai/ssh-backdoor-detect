#pragma once
#include "../pam_task.h"

static std::string uppercase(std::string& s) {
  std::string ret = s;
  for (int i = 0; i < ret.size(); i++) {
    ret[i] = std::toupper(ret[i]);
  }
  return ret;
}

class pam_func_handler {
public:
  virtual std::string attach_func_name() = 0;
  virtual void handle(pam_event_t* event) {
    LOG4CPLUS_INFO_FMT(logger, "[%s] -> %d", attach_func_name().c_str(), event->ret);
  };

  std::string attach_func_type_variable() {
    auto name = attach_func_name();
    return uppercase(name);
  }

  pam_func_handler(bpf_probe_attach_type t) : attach_type(t) {
    logger = log4cplus::Logger::getInstance("default");
  };
  virtual ~pam_func_handler(){};

  bpf_probe_attach_type attach_type;
  log4cplus::Logger logger;
};
