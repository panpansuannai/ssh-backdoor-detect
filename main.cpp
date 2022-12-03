// use libbpfcc v0.18

#include <bcc/BPF.h>
#include <bcc/bcc_version.h>
#include <log4cplus/appender.h>
#include <log4cplus/consoleappender.h>
#include <log4cplus/helpers/pointer.h>
#include <log4cplus/layout.h>
#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/loglevel.h>
#include <unistd.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>

#include "bpf_task.h"
#include "path.h"
#include "tasks/openpty_task.h"
#include "tasks/pam_task.h"

log4cplus::Logger initialize_logger() {
  using namespace log4cplus;
  using namespace std;

  helpers::SharedObjectPtr<Appender> appender(new ConsoleAppender());
  appender->setName("STDOUT");

  appender->setLayout(unique_ptr<Layout>(
      new PatternLayout("%d{%Y/%m/%d %H:%M:%S} - (%l): %m%n")));

  auto logger = Logger::getInstance("default");
  logger.addAppender(appender);
  logger.setLogLevel(ALL_LOG_LEVEL);
  return logger;
}

int main() {
  log4cplus::Logger logger = initialize_logger();
  LOG4CPLUS_DEBUG(logger, "[Start]");

  // auto openpty_task = get_openpty_task(logger);
  // if (openpty_task == nullptr) {
  //   logger.log(log4cplus::ERROR_LOG_LEVEL, "Empty openpty task");
  //   return 0;
  // }
  auto pam_task = get_pam_task();
  if (pam_task == nullptr) {
    LOG4CPLUS_ERROR(logger, "Empty pam task");
    return 0;
  }
  LOG4CPLUS_INFO(logger, "Start to create threads");
  // std::thread t1([&]() { openpty_task->poll_loop(); });
  std::thread t2([&]() { pam_task->poll_loop(); });

  LOG4CPLUS_INFO(logger, "Wait for threads");
  // t1.join();
  t2.join();

  // delete openpty_task;
  delete pam_task;
  return 0;
}
