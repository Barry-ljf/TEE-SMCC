#pragma once
#include <glog/logging.h>

#include <condition_variable>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "status.h"

namespace smcc {
struct Context1 {
  int party_id;
  std::string next_party;
  std::string prev_party;

  uint64_t nextseed;
  uint64_t prevseed;
  sgx_enclave_id_t eid;

  std::string A, p, g, B;

  std::map<std::string, std::vector<std::string>> datasets;

  bool status_update;
  std::queue<std::string> task_queue;
  std::mutex mtx_1;
  std::condition_variable cv_1;

  std::map<std::string, Status> task_status;
  std::mutex mtx_2;
  std::condition_variable cv_2;

  std::string pubkey_e;
  std::string pubkey_n;

  std::thread manage_thread_;

  Context1() {}
  Context1(const Context1 &ctx1_val) { eid = ctx1_val.eid; }
};

void runCompute(std::string jobid);
Status getJobContext(const std::string &jobid, Context1 **job_context);
Status insertJobContext(const std::string &jobid, const Context1 &job_context);
Status destroyJobContext(const std::string &jobid);
}  // namespace smcc
