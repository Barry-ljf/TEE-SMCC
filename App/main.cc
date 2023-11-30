#include <glog/logging.h>
#include <grpcpp/grpcpp.h>

#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "server.h"
#include "sgx_urts.h"

using namespace std;

void runServer(std::vector<std::string> &party_ip, int party_id) {
  smcc::SMCCServiceImpl service;
  std::string &next_party = party_ip[(party_id + 1) % 3];
  std::string &prev_party = party_ip[(party_id + 2) % 3];

  service.setParty(party_id, next_party, prev_party);

  string server_address = party_ip[party_id];
  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();
}

int main(int argc, char *argv[]) {
  google::InitGoogleLogging(argv[0]);
  FLAGS_colorlogtostderr = true;
  FLAGS_alsologtostderr = true;

  int party_id = atoi(argv[1]);
  std::vector<std::string> party_ip{"127.0.0.1:5000", "127.0.0.1:6000",
                                    "127.0.0.1:7000"};

  auto server_fn = [&party_ip, party_id]() { runServer(party_ip, party_id); };

  LOG(INFO) << "Start party " << party_id << ".";

  std::thread server_thread(server_fn);
  server_thread.join();

  return 0;
}
