#include "server.h"

#include <grpcpp/grpcpp.h>
#include <pthread.h>

#include <chrono>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "smcc.grpc.pb.h"
#include "smcc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

namespace smcc {
extern std::map<std::string, Context1> cpu_context;
extern pthread_rwlock_t cpu_context_lock;

void SMCCServiceImpl::setParty(int party_id, const std::string &next_party,
                               const std::string &prev_party) {
  this->party_id_ = party_id;
  this->next_party_ = next_party;
  this->prev_party_ = prev_party;
}

grpc::Status SMCCServiceImpl::initJob(grpc::ServerContext *context,
                                      const rpc::InitJobRequest *request,
                                      rpc::InitJobResponse *response) {
  std::string jobid = request->jobid();
  LOG(INFO) << "Init job, jobid " << jobid << ".";

  // Create enclave.
  sgx_enclave_id_t eid = 0;
  sgx_status_t sgx_status = sgx_create_enclave("Enclave/Enclave.signed.so", 0,
                                               NULL, NULL, &eid, NULL);
  if (sgx_status != SGX_SUCCESS) {
    LOG(ERROR) << "Create enclave failed, sgx error " << sgx_status << ".";
    response->set_error(true);
    response->set_msg("Create enclave failed");
    return grpc::Status::OK;
  }

  Context1 *job_context = nullptr;
  auto status = getJobContext(jobid, &job_context);
  if (status.IsOK()) {
    std::stringstream ss;
    ss << "Fatal error, another job has the same jobid " << jobid;
    response->set_msg(ss.str());
    response->set_error(true);
    LOG(ERROR) << ss.str() << ".";
    return grpc::Status::OK;
  }

  Context1 tmp_context;
  tmp_context.eid = eid;

  insertJobContext(jobid, tmp_context);
  getJobContext(jobid, &job_context);

  // Start management thread.
  job_context->manage_thread_ = std::thread(runCompute, jobid);

  job_context->party_id = this->party_id_;
  job_context->next_party = this->next_party_;
  job_context->prev_party = this->prev_party_;

  // Exchange seed for secure share generation.
  std::string task_name = "InitOpenssl";
  issueTask(job_context, task_name);
  waitTaskDone(job_context, task_name);

  auto status_iter = job_context->task_status.find(task_name);
  status = status_iter->second;
  if (!status.IsOK()) {
    std::stringstream ss;
    ss << "Task " << task_name << " failed, Error: " << status.getMessage();
    LOG(ERROR) << ss.str() << ".";
    response->set_msg(ss.str());
    response->set_error(true);
    return grpc::Status::OK;
  }

  // Generate RSA key.
  task_name = "GenRSAKey";
  issueTask(job_context, task_name);
  waitTaskDone(job_context, task_name);

  status_iter = job_context->task_status.find(task_name);
  status = status_iter->second;
  if (!status.IsOK()) {
    std::stringstream ss;
    ss << "Task " << task_name << " failed, Error: " << status.getMessage();
    LOG(ERROR) << ss.str() << ".";
    response->set_msg(ss.str());
    response->set_error(true);
    return grpc::Status::OK;
  }

  // Generate seed.
  task_name = "InitSeed";
  issueTask(job_context, task_name);
  waitTaskDone(job_context, task_name);

  status_iter = job_context->task_status.find(task_name);
  status = status_iter->second;
  if (!status.IsOK()) {
    std::stringstream ss;
    ss << "Task " << task_name << " failed, Error: " << status.getMessage();
    LOG(ERROR) << ss.str() << ".";
    response->set_msg(ss.str());
    response->set_error(true);
    return grpc::Status::OK;
  }

  // Generate DH exchange algorithm .
  task_name = "DHKeyExchange";
  issueTask(job_context, task_name);
  waitTaskDone(job_context, task_name);

  status_iter = job_context->task_status.find(task_name);
  status = status_iter->second;
  if (!status.IsOK()) {
    std::stringstream ss;
    ss << "Task " << task_name << " failed, Error: " << status.getMessage();
    LOG(ERROR) << ss.str() << ".";
    response->set_msg(ss.str());
    response->set_error(true);
    return grpc::Status::OK;
  }

  response->set_error(false);
  response->set_msg("Finish without error.");

  // TODO: Run DH.
  // Generate AES key.
  // task_name = "GenAESKey";
  // issueTask(job_context, task_name);
  // waitTaskDone(job_context, task_name);

  return grpc::Status::OK;
}

grpc::Status SMCCServiceImpl::destroyJob(grpc::ServerContext *context,
                                         const rpc::DestroyJobRequest *request,
                                         rpc::DestroyJobResponse *response) {
  const std::string &jobid = request->jobid();
  Status status = waitJobContextReady(jobid);
  if (!status.IsOK()) {
    response->set_msg(status.getMessage());
    response->set_error(true);
    LOG(ERROR) << status.getMessage() << ".";
    return grpc::Status::OK;
  }

  Context1 *job_context = nullptr;
  status = getJobContext(jobid, &job_context);
  if (!status.IsOK()) {
    std::stringstream ss;
    ss << "There is no job with jobid " << jobid << ".";
    response->set_error(true);
    response->set_msg(ss.str());
    return grpc::Status::OK;
  }

  // Stop management thread.
  std::string task_name = "StopJob";
  issueTask(job_context, task_name);
  waitTaskDone(job_context, task_name);

  job_context->manage_thread_.join();
  LOG(INFO) << "Stop management thread of job " << jobid << ".";

  // Destroy enclave.
  sgx_status_t sgx_status = sgx_destroy_enclave(job_context->eid);
  if (sgx_status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Destroy enclave for job " << jobid << " failed";
    response->set_msg(ss.str());
    response->set_error(true);
    LOG(ERROR) << ss.str() << ", sgx error " << sgx_status << ".";
  }

  LOG(INFO) << "Destroy enclave of job " << jobid << ".";

  // Destroy context1.
  destroyJobContext(jobid);
  LOG(INFO) << "Destroy context1 of job " << jobid << ".";

  return grpc::Status::OK;
}

grpc::Status SMCCServiceImpl::sendSeed(grpc::ServerContext *context,
                                       const rpc::SeedRequest *request,
                                       rpc::SeedResponse *response) {
  const std::string &jobid = request->jobid();
  uint64_t seed = request->seed();
  std::cout << "send_seed: " << seed << std::endl;
  auto status = waitJobContextReady(jobid);
  if (!status.IsOK()) {
    response->set_msg(status.getMessage());
    response->set_error(true);
    LOG(ERROR) << status.getMessage() << ".";
    return grpc::Status::OK;
  }

  Context1 *job_context = nullptr;
  getJobContext(jobid, &job_context);

  job_context->prevseed = seed;

  {
    std::unique_lock<std::mutex> lock(job_context->mtx_1);
    job_context->cv_1.notify_all();
  }

  response->set_error(false);
  response->set_msg("No error.");

  LOG(INFO) << "RPC receive encrypted seed, jobid " << jobid << ".";
  return grpc::Status::OK;
}

grpc::Status SMCCServiceImpl::sendDHParamA(grpc::ServerContext *context,
                                           const rpc::DHParamARequest *request,
                                           rpc::DHParamAResponse *response) {
  const std::string &jobid = request->jobid();
  std::string g = request->g();
  std::string A = request->a();
  std::string p = request->p();
  std::cout << "send_A: " << A << std::endl;
  auto status = waitJobContextReady(jobid);
  if (!status.IsOK()) {
    response->set_msg(status.getMessage());
    response->set_error(true);
    LOG(ERROR) << status.getMessage() << ".";
    return grpc::Status::OK;
  }

  Context1 *job_context = nullptr;
  getJobContext(jobid, &job_context);

  job_context->g = g;
  job_context->A = A;
  job_context->p = p;

  {
    std::unique_lock<std::mutex> lock(job_context->mtx_1);
    job_context->cv_1.notify_all();
  }

  response->set_error(false);
  response->set_msg("No error.");

  LOG(INFO) << "RPC receive encrypted g a p, jobid " << jobid << ".";
  return grpc::Status::OK;
}

grpc::Status SMCCServiceImpl::sendDHParamB(grpc::ServerContext *context,
                                           const rpc::DHParamBRequest *request,
                                           rpc::DHParamBResponse *response) {
  const std::string &jobid = request->jobid();
  std::string B = request->b();

  auto status = waitJobContextReady(jobid);
  if (!status.IsOK()) {
    response->set_msg(status.getMessage());
    response->set_error(true);
    LOG(ERROR) << status.getMessage() << ".";
    return grpc::Status::OK;
  }

  Context1 *job_context = nullptr;
  getJobContext(jobid, &job_context);

  job_context->B = B;

  {
    std::unique_lock<std::mutex> lock(job_context->mtx_1);
    job_context->cv_1.notify_all();
  }

  response->set_error(false);
  response->set_msg("No error.");

  LOG(INFO) << "RPC receive PUBKEY B, jobid " << jobid << ".";
  return grpc::Status::OK;
}

grpc::Status SMCCServiceImpl::requestPublicKey(
    grpc::ServerContext *context, const rpc::PubKeyRequest *request,
    rpc::PubKeyResponse *response) {
  return grpc::Status::OK;
}

grpc::Status SMCCServiceImpl::uploadRSS(
    grpc::ServerContext *context,
    grpc::ServerReaderWriter<rpc::RssResponse, rpc::RssRequest> *stream) {
  rpc::RssRequest rss_req;
  bool is_first = true;

  std::string jobID;
  std::string dataID;

  while (stream->Read(&rss_req)) {
    jobID = rss_req.jobid();
    dataID = rss_req.dataid();
    // std::unique_lock<std::mutex>
    // lock_1(cpu_context.find(jobID)->second.mtx_1);
    // auto status = waitJobContextReady(jobID);
    // if (!status.IsOK()) {
    //   // jobID is not exist
    //   rpc::RssResponse rss_res;
    //   rss_res.set_status(1);
    //   rss_res.set_msg(status.getMessage());
    //   stream->Write(rss_res);

    //   return grpc::Status::OK;
    // }

    Context1 *job_context = nullptr;

    auto status = getJobContext(jobID, &job_context);
    if (!status.IsOK()) {
      // jobID is not exist
      rpc::RssResponse rss_res;
      rss_res.set_status(1);
      std::string msg(
          "upload datasets failed! jobID is not exist,please create jobID "
          "first!");
      rss_res.set_msg(msg);
      stream->Write(rss_res);

      return grpc::Status::OK;
    }

    // std::unique_lock<std::mutex> lock(job_context->mtx_1);
    auto datasets_iter = job_context->datasets.find(dataID);
    if (is_first == true && datasets_iter != job_context->datasets.end()) {
      // this dataid has existed
      // job_context->cv_1.notify_all();
      // lock.unlock();
      {
        std::unique_lock<std::mutex> lock(job_context->mtx_1);
        job_context->cv_1.notify_all();
      }
      rpc::RssResponse rss_res;
      rss_res.set_status(1);
      std::string msg("upload datasets failed! this dataid has existed!");
      rss_res.set_msg(msg);
      stream->Write(rss_res);

      return grpc::Status::OK;
    }
    // map insert dataID
    if (is_first == true) {
      std::vector<std::string> dataID_vec;
      job_context->datasets.emplace(dataID, dataID_vec);
      is_first = false;
    }
    datasets_iter = job_context->datasets.find(dataID);
    for (int i = 0; i < rss_req.dataval_size(); i++) {
      datasets_iter->second.push_back(rss_req.dataval(i));
      // std::cout << datasets_iter->second.size() << endl;
    }
    // cpu_context.find(jobID)->second.cv_1.notify_all();
    // lock_1.unlock();
    {
      std::unique_lock<std::mutex> lock(job_context->mtx_1);
      job_context->cv_1.notify_all();
    }

    // success
    rpc::RssResponse rss_res;
    rss_res.set_status(0);
    std::string msg("upload datasets success!");
    rss_res.set_msg(msg);
    stream->Write(rss_res);
  }

  Context1 *job_context = nullptr;
  getJobContext(jobID, &job_context);
  auto datasets_iter = job_context->datasets.find(dataID);

  LOG(INFO) << "datasets size: " << datasets_iter->second.size();

  for (int i = 0; i < datasets_iter->second.size(); i++) {
    LOG(INFO) << "datasets data: " << datasets_iter->second[i];
  }

  return grpc::Status::OK;
}

void SMCCServiceImpl::issueTask(Context1 *job_context,
                                const std::string &task_name) {
  std::unique_lock<std::mutex> lock(job_context->mtx_1);
  job_context->task_status.insert(
      std::make_pair(task_name, Status::UnavailableError("Not inited.")));
  job_context->status_update = false;
  job_context->task_queue.push(task_name);
  job_context->cv_1.notify_all();
}

void SMCCServiceImpl::waitTaskDone(Context1 *job_context,
                                   const std::string &task_name) {
  std::unique_lock<std::mutex> lock(job_context->mtx_2);
  job_context->cv_2.wait(
      lock, [job_context]() { return job_context->status_update == true; });
  job_context->status_update = false;
}

Status SMCCServiceImpl::waitJobContextReady(const std::string &jobid) {
  Context1 *job_context = nullptr;
  uint16_t num_try = 300;

  Status status = getJobContext(jobid, &job_context);
  if (status.IsOK()) return Status::OK();

  LOG(WARNING) << "Context1 of job " << jobid << " is not ready.";

  while (num_try != 0) {
    status = getJobContext(jobid, &job_context);
    if (status.IsOK()) break;

    num_try--;

    if (num_try % 100 == 0)
      LOG(WARNING) << "Context1 of job " << jobid << " is not ready.";

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  if (job_context != nullptr) {
    return Status::OK();
  } else {
    std::stringstream ss;
    ss << "Waiting for context1 of the job " << jobid
       << " has exceeded the timeout";
    return Status::TimeoutError(ss.str());
  }
}

}  // namespace smcc
