// use libbpfcc v0.12

#include <unistd.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <chrono>
#include <thread>

//#include "bcc_version.h"
#include <bcc/BPF.h>

#include <spdlog/spdlog.h>

#include "path.h"
#include "bpf_task.h"
#include "tasks/openpty_task.h"
#include "tasks/pam_task.h"

int main() {
  auto pam_task = get_pam_task();
  if(pam_task == nullptr) {
    return 0;
  }
  auto openpty_task = get_openpty_task();
  if(openpty_task == nullptr) {
    return 0;
  }
  std::thread pam_thread([&]() {
    pam_task->poll_loop();
  });
  std::thread openpty_thread([&]() {
    openpty_task->poll_loop();
  });
  pam_thread.join();
  openpty_thread.join();
  delete pam_task;
  delete openpty_task;
  return 0;
}
