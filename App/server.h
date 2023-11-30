#pragma once
#include <glog/logging.h>
#include <time.h>

#include <thread>

#include "Enclave_u.h"
#include "management.h"
#include "sgx_urts.h"
#include "smcc.grpc.pb.h"
#include "smcc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

namespace smcc {

class SMCCServiceImpl : public rpc::SMCCService::Service {
 public:
  SMCCServiceImpl(){};
  ~SMCCServiceImpl(){};

  void setParty(int party_id, const std::string &next_party,
                const std::string &prev_party);

  grpc::Status initJob(grpc::ServerContext *context,
                       const rpc::InitJobRequest *request,
                       rpc::InitJobResponse *response) override;

  grpc::Status destroyJob(grpc::ServerContext *context,
                          const rpc::DestroyJobRequest *request,
                          rpc::DestroyJobResponse *response);

  grpc::Status sendSeed(grpc::ServerContext *context,
                        const rpc::SeedRequest *request,
                        rpc::SeedResponse *response) override;

  grpc::Status sendDHParamA(grpc::ServerContext *context,
                            const rpc::DHParamARequest *request,
                            rpc::DHParamAResponse *response) override;

  grpc::Status sendDHParamB(grpc::ServerContext *context,
                            const rpc::DHParamBRequest *request,
                            rpc::DHParamBResponse *response) override;

  grpc::Status requestPublicKey(grpc::ServerContext *context,
                                const rpc::PubKeyRequest *request,
                                rpc::PubKeyResponse *response) override;
  grpc::Status uploadRSS(
      grpc::ServerContext *context,
      grpc::ServerReaderWriter<rpc::RssResponse, rpc::RssRequest> *stream);

 private:
  Status waitJobContextReady(const std::string &task_name);
  void issueTask(Context1 *job_context, const std::string &task_name);
  void waitTaskDone(Context1 *job_context, const std::string &task_name);

  int party_id_;
  std::string next_party_;
  std::string prev_party_;
};
}  // namespace smcc
