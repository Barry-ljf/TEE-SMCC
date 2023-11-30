#include <grpcpp/grpcpp.h>  // 和python一样, import grp

#include <iostream>
#include <memory>
#include <string>

// 在包含两个信息和应用的头文件
#include "Enclave_u.h"
#include "seed.grpc.pb.h"
#include "seed.pb.h"
#include "sgx_urts.h"

// 这是通用工具
using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;

using namespace std;

sgx_enclave_id_t eid = 0;

class seedClient {
 private:
  unique_ptr<SeedService::Stub> stub_;

 public:
  seedClient(std::shared_ptr<Channel> channel)
      : stub_(SeedService::NewStub(channel)) {}

  void ClientStream() {
    ClientContext context;
    SeedResponse response;
    shared_ptr<ClientReaderWriter<SeedRequest, SeedResponse>> stream(
        stub_->sendseed(&context));
    for (int i = 0; i < 5; i++) {
      SeedRequest request;
      uint64_t seed_;
      ecall_gen_seed(eid, &seed_);
      request.set_seed(seed_);
      stream->Write(request);
      SeedResponse response;
      stream->Read(&response);
      printf("msg:%s seed: %ld\n", response.msg(), response.seed());
    }

    stream->WritesDone();
    Status status = stream->Finish();
    if (status.ok()) {
      printf("send seed successfully!\n");
    } else {
      printf("failed to send seed\n");
    }
  }
};

int main() {
  sgx_status_t status = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG,
                                           NULL, NULL, &eid, NULL);
  if (status != SGX_SUCCESS) {
    // Handle error
    // cout<<status<<endl;
    printf("%x\n", status);
    printf("Enclave create error!\n");
    return -1;
  }

  std::string server_address("127.0.0.1:50051");
  seedClient client(
      grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials()));
  client.ClientStream();
  return 0;
}

/*
class YourClient {
public:
    YourClient(std::shared_ptr<Channel> channel)
        : stub_(YourService::NewStub(channel)) {}

    void BidirectionalStream() {
        ClientContext context;
        std::shared_ptr<ClientReaderWriter<YourRequest, YourResponse>> stream(
            stub_->BidirectionalStream(&context));

        // Send multiple requests
        for (int i = 0; i < 5; i++) {
            YourRequest request;
            // Set request data
            // ...

            stream->Write(request);
            YourResponse response;
            stream->Read(&response);
            // Process the response
            // ...
        }

        stream->WritesDone();
        Status status = stream->Finish();
        if (status.ok()) {
            std::cout << "Bidirectional streaming completed successfully." <<
std::endl; } else { std::cout << "Bidirectional streaming failed with error: "
<< status.error_message() << std::endl;
        }
    }

private:
    std::unique_ptr<YourService::Stub> stub_;
};

int main() {
    std::string server_address("localhost:50051");
    YourClient client(grpc::CreateChannel(server_address,
grpc::InsecureChannelCredentials())); client.BidirectionalStream(); return 0;
}
客户端*/

// service MsgService { // 定义服务, 流数据放到括号里面
//   rpc GetMsg (MsgRequest) returns (MsgResponse){}
// }

// message MsgRequest { // 请求的结构, 也可以定义int32，int64，double，float
//   string name = 1;
//   int32 num1 = 2;
//   double num2 = 3;
// }

// message MsgResponse { // 回应的结果
//   string msg = 1;
//   int32 num1 = 2;
//   double num2 = 3;
// }
//
// 不知道为啥, 这里生成并没有定义namespace, 所以可以在引用头文件之后直接使用
// using msg::MsgRequest; //上面定义的请求结构
// using msg::MsgResponse; // 上面定义的响应结构
// using msg::MsgService; // 上面定义的类

/*
class MsgServiceClient {
 public:
  MsgServiceClient(std::shared_ptr<Channel> channel)
      : stub_(MsgService::NewStub(channel)) {}


  MsgResponse GetMsg(const std::string& user, int num1, double num2) {
    // 请求数据数据格式化到request
    MsgRequest request;
    request.set_name(user);
    request.set_num1(num1);
    request.set_num2(num2);

    // 服务器返回端
    MsgResponse reply;

    //客户端上下文。它可以用来传递额外的信息
    //服务器和/或调整某些RPC行为。
    ClientContext context;

    // The actual RPC.
    Status status = stub_->GetMsg(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      // std::cout<<reply.msg()<<std::endl;
      // printf("num1 = %d;  num2=%f\n", reply.num1(), reply.num2());
      // return reply.msg();  // reply.msg(), reply.num1(), reply.num2();
      return reply;  // reply.msg(), reply.num1(), reply.num2();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return reply;
    }
  }

 private:
  std::unique_ptr<MsgService::Stub> stub_;
};*/
/*
int main(int argc, char** argv) {
  MsgServiceClient z_msg(grpc::CreateChannel(
      "192.168.99.46:50051", grpc::InsecureChannelCredentials()));
  std::string user("world");
  // std::string reply = z_msg.GetMsg(user, 234, 3.1415926);
  MsgResponse reply = z_msg.GetMsg(user, 234, 3.1415926);
  std::cout<<reply.msg()<<std::endl;
  printf("num1 = %d;  num2=%f\n", reply.num1(), reply.num2());
  // std::cout << "Greeter received: " << reply << std::endl;
  return 0;
}*/
