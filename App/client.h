#pragma once
#include <glog/logging.h>
#include <grpcpp/grpcpp.h>

#include <iostream>
#include <memory>
#include <string>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "smcc.grpc.pb.h"
#include "smcc.pb.h"
#include "status.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;

using namespace std;

namespace smcc {
class TransferClient {
 public:
  TransferClient(std::shared_ptr<Channel> channel)
      : stub_(rpc::SMCCService::NewStub(channel)) {}

  Status SendSeed(uint64_t send_seed, std::string jobid) {
    ClientContext context;

    rpc::SeedRequest request;
    request.set_seed(send_seed);
    request.set_jobid(jobid);
    std::cout << "send_seed: " << send_seed << std::endl;
    rpc::SeedResponse response;
    grpc::Status status = stub_->sendSeed(&context, request, &response);
    if (!status.ok()) {
      LOG(ERROR) << "Send seed to peer failed.";
      return Status::RPCError("Send seed to peer failed");
    }

    if (response.error() == true) {
      LOG(ERROR) << "Server error: " << response.msg() << ".";
      return Status::InternalError(response.msg());
    }

    return Status::OK();
  }

  Status SendDHParamA(std::string send_A, std::string send_p,
                      std::string send_g, std::string jobid) {
    ClientContext context;

    rpc::DHParamARequest request;
    request.set_g(send_g);
    request.set_a(send_A);
    request.set_p(send_p);
    request.set_jobid(jobid);
    std::cout << "send_A: " << send_A << std::endl;
    rpc::DHParamAResponse response;
    grpc::Status status = stub_->sendDHParamA(&context, request, &response);
    if (!status.ok()) {
      LOG(ERROR) << "Send g,A,p to peer failed.";
      return Status::RPCError("Send g,A,p to peer failed");
    }

    if (response.error() == true) {
      LOG(ERROR) << "Server error: " << response.msg() << ".";
      return Status::InternalError(response.msg());
    }

    return Status::OK();
  }

  Status SendDHParamB(std::string send_B, std::string jobid) {
    ClientContext context;

    rpc::DHParamBRequest request;
    request.set_b(send_B);
    request.set_jobid(jobid);

    rpc::DHParamBResponse response;
    grpc::Status status = stub_->sendDHParamB(&context, request, &response);
    if (!status.ok()) {
      LOG(ERROR) << "Send B to peer failed.";
      return Status::RPCError("Send B to peer failed");
    }

    if (response.error() == true) {
      LOG(ERROR) << "Server error: " << response.msg() << ".";
      return Status::InternalError(response.msg());
    }

    return Status::OK();
  }

 private:
  std::unique_ptr<rpc::SMCCService::Stub> stub_;
};
}  // namespace smcc
