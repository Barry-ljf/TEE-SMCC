#include "management.h"

#include <pthread.h>

#include <condition_variable>
#include <map>
#include <mutex>
#include <string>

#include "client.h"

namespace smcc {
namespace {
std::map<std::string, Context1> cpu_context;
pthread_rwlock_t cpu_context_lock = PTHREAD_RWLOCK_INITIALIZER;
};  // namespace

Status getJobContext(const std::string &jobid, Context1 **job_context) {
  pthread_rwlock_rdlock(&cpu_context_lock);
  auto iter = cpu_context.find(jobid);
  if (iter == cpu_context.end()) {
    *job_context = nullptr;
    pthread_rwlock_unlock(&cpu_context_lock);

    std::stringstream ss;
    return Status::NotFoundError("Not found");
  }

  *job_context = &(iter->second);
  pthread_rwlock_unlock(&cpu_context_lock);
  return Status::OK();
}

Status insertJobContext(const std::string &jobid, const Context1 &job_context) {
  pthread_rwlock_wrlock(&cpu_context_lock);
  auto iter = cpu_context.find(jobid);
  if (iter != cpu_context.end()) {
    pthread_rwlock_unlock(&cpu_context_lock);
    std::stringstream ss;
    ss << "Another job has the same jobid " << jobid;
    return Status::DuplicateError(ss.str());
  }

  cpu_context.insert(std::make_pair(jobid, job_context));

  pthread_rwlock_unlock(&cpu_context_lock);
  return Status::OK();
}

Status destroyJobContext(const std::string &jobid) {
  pthread_rwlock_wrlock(&cpu_context_lock);
  auto iter = cpu_context.find(jobid);
  if (iter == cpu_context.end()) {
    pthread_rwlock_unlock(&cpu_context_lock);
    std::stringstream ss;
    ss << "There is no job with jobid " << jobid;
    return Status::NotFoundError(ss.str());
  }

  cpu_context.erase(iter);
  pthread_rwlock_unlock(&cpu_context_lock);
  return Status::OK();
}

static void setTaskStatus(Context1 *context, const std::string &task_name,
                          Status status) {
  std::mutex &mu = context->mtx_2;
  std::condition_variable &cv = context->cv_2;

  auto iter = context->task_status.find(task_name);
  iter->second = status;

  context->status_update = true;
  std::unique_lock<std::mutex> lock(mu);
  cv.notify_all();
}

void runCompute(std::string jobid) {
  sgx_status_t status;
  // Context1 &job_context = cpu_context.find(jobid)->second;
  Context1 *job_context = nullptr;
  getJobContext(jobid, &job_context);

  sgx_enclave_id_t local_eid = job_context->eid;

  std::mutex &mtx_1 = job_context->mtx_1;
  std::mutex &mtx_2 = job_context->mtx_2;

  std::condition_variable &cv_1 = job_context->cv_1;
  std::condition_variable &cv_2 = job_context->cv_2;

  std::queue<std::string> &task_queue = job_context->task_queue;

  while (true) {
    std::string task_name;
    {
      std::unique_lock<std::mutex> lock_1(mtx_1);
      cv_1.wait(lock_1, [jobid, &task_queue] { return !task_queue.empty(); });
      task_name = task_queue.front();
      task_queue.pop();
    }

    LOG(INFO) << "Run task " << task_name << ", jobid " << jobid << ".";
    if (task_name == "InitOpenssl") {
      status = ecall_init_openssl(local_eid);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Init openssl failed");
        setTaskStatus(job_context, task_name, error);
        LOG(ERROR) << "Init openssl failed, sgx error " << status << ", jobid "
                   << jobid << ".";
        continue;
      } else {
        setTaskStatus(job_context, task_name, Status::OK());
        LOG(INFO) << "Init openssl library finish, jobid " << jobid << ".";
      }
    } else if (task_name == "GenRSAKey") {
      // 1.[ecall] Generate RSA private key and public key.
      status = ecall_rsa_key_gen(local_eid);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError(
            "Generate RSA private key and public key failed");
        setTaskStatus(job_context, task_name, error);
        LOG(ERROR)
            << "Generate RSA private key and public key failed, sgx error "
            << status << ", jobid " << jobid << ".";
        continue;
      } else {
        setTaskStatus(job_context, task_name, Status::OK());
        LOG(INFO) << "Generate RSA public key finish, jobid " << jobid << ".";
      }
    } else if (task_name == "InitSeed") {
      // 1.[ecall] Generate seed;
      // 2.[ecall] Copy encrypted seed from enclave;
      // 3.Send encrypted seed to next party;
      // 4.Recv encrypted seed from prev party;
      // 5.[ecall] Generate lots of zero shares;
      // 6.Notify RPC call that task is done;
      status = ecall_gen_seed(local_eid);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Generate seed failed");
        setTaskStatus(job_context, task_name, error);
        LOG(ERROR) << "Generate seed failed, jobid " << jobid << ".";
        continue;
      }

      uint64_t encryted_seed;
      status = ecall_get_nextSeed(local_eid, &encryted_seed, 8);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Get encrypted seed failed");
        setTaskStatus(job_context, task_name, error);
        LOG(ERROR) << "Get encrypted seed failed, jobid " << jobid << ".";
        continue;
      }

      LOG(INFO) << "Encrypted seed sending to next party is " << encryted_seed
                << ", jobid " << jobid << ".";

      auto channel = grpc::CreateChannel(job_context->next_party,
                                         grpc::InsecureChannelCredentials());
      TransferClient client(channel);
      auto ret = client.SendSeed(encryted_seed, jobid);
      if (!ret.IsOK()) {
        LOG(ERROR) << "Send encrypted seed to " << job_context->next_party
                   << " failed, jobid " << jobid << ".";
        setTaskStatus(job_context, task_name, ret);
        continue;
      }

      {
        std::unique_lock<std::mutex> lock(mtx_1);
        cv_1.wait(lock, [job_context] { return job_context->prevseed != 0; });
      }

      uint64_t &prev_seed = job_context->prevseed;

      LOG(INFO) << "Encrypted seed from prev party is " << prev_seed
                << ", jobid " << jobid << ".";

      status = ecall_set_prevSeed(local_eid, prev_seed);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Store seed from prev party failed");
        setTaskStatus(job_context, task_name, error);
        LOG(ERROR) << "Store seed from prev party failed, jobid " << jobid
                   << ".";
        continue;
      }

      status = ecall_AES_generate(local_eid, 256);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Generate zero share failed");
        setTaskStatus(job_context, task_name, error);
        LOG(ERROR) << "Generate zero share failed, jobid " << jobid << ".";
        continue;
      }

      setTaskStatus(job_context, task_name, Status::OK());
      LOG(INFO) << "Task " << task_name << " finish, jobid " << jobid << ".";
    } else if (task_name == "GetPublicKey") {
      // 1.[ecall] Get public key size;
      // 2.[ecall] Get public key string;
      // 3.Return to RPC call.
      size_t size_n = 0;
      size_t size_e = 0;
      status = ecall_get_pubkey_size(local_eid, &size_n, &size_e);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Get public key size failed");
        setTaskStatus(job_context, task_name, error);
        task_queue.pop();
        LOG(ERROR) << "Get public key size failed, jobid " << jobid << ".";
        continue;
      }

      std::string pubkey_n, pubkey_e;
      pubkey_n.resize(size_n);
      pubkey_e.resize(size_e);

      char *str_n = const_cast<char *>(pubkey_n.data());
      char *str_e = const_cast<char *>(pubkey_e.data());
      status = ecall_get_pubkey(local_eid, str_e, str_n, size_e, size_n);
      if (status != SGX_SUCCESS) {
        Status error = Status::EcallError("Get public key failed");
        setTaskStatus(job_context, task_name, error);
        task_queue.pop();
        LOG(ERROR) << "Get public key failed, jobid " << jobid << ".";
        continue;
      }

      job_context->pubkey_e = std::move(pubkey_e);
      job_context->pubkey_n = std::move(pubkey_n);

      setTaskStatus(job_context, task_name, Status::OK());
      task_queue.pop();
    } else if (task_name == "DHKeyExchange") {
      // for common parties:
      size_t size_prevkey, size_nextkey;

      // 1. p0,p1 generate and get g,A,p.
      if (job_context->party_id == 0) {
        size_t size_A, size_p, size_g;
        char str_A[1024], str_p[1024], str_g[1024];
        char str_B01[1024], str_B02[1024];

        sgx_status_t status = ecall_dh_stage_1(local_eid);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey gen failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }
        status = ecall_dh_stage_1_parametersize(local_eid, &size_A, &size_p,
                                                &size_g);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey get parametersize failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_A += 1;
        size_p += 1;
        size_g += 1;

        status = ecall_dh_stage_1_getparameter(local_eid, str_A, str_p, str_g,
                                               size_A, size_p, size_g);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey get parameter failed, sgx error " << status
             << "job_context->party_id " << job_context->party_id << ".";
          throw std::runtime_error(ss.str());
        }

        // 2.send and recv g ,A and p to party 2.
        std::string string_A = str_A;
        std::string string_p = str_p;
        std::string string_g = str_g;
        std::cout << "string_A :" << string_A << std::endl;

        // send to p2's ip port str_A,str_p,str_g;
        auto channel2 = grpc::CreateChannel(job_context->prev_party,
                                            grpc::InsecureChannelCredentials());
        TransferClient client2(channel2);

        auto sendparamA02ret =
            client2.SendDHParamA(string_A, string_p, string_g, jobid);
        if (!sendparamA02ret.IsOK()) {
          LOG(ERROR) << "Send str_g, str_A, str_p to "
                     << job_context->prev_party << " failed, jobid " << jobid
                     << ".";
          setTaskStatus(job_context, task_name, sendparamA02ret);
          continue;
        }

        {
          std::unique_lock<std::mutex> lock(mtx_1);
          cv_1.wait(lock,
                    [job_context] { return job_context->B.length() != 0; });
        }
        std::cout << "run here: recvB02" << std::endl;
        std::cout << "recvB02:" << job_context->B << std::endl;
        // 3.send and recv B from party 2 DH exchange .
        // recv from p2's port(listen p2's next port),get strB_02
        std::string string_B02 = job_context->B;
        memcpy(str_B02, const_cast<char *>(string_B02.c_str()),
               string_B02.size());
        // 4.using recv strB02 to gen prev_key
        str_B02[strlen(string_B02.c_str())] = '\0';
        size_t size_B02 = strlen(str_B02) + 1;

        status = ecall_dh_stage_3(local_eid, str_B02, size_B02);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P0 ecall_dh_stage_3 from enclave failed, sgx error " << status
             << ".";
          throw std::runtime_error(ss.str());
        }
        // 5.using B to generate the key.
        status = ecall_dh_stage_3_getkeysize(local_eid, &size_prevkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P0 ecall_dh_stage_3_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_prevkey += 1;
        char *str_prevkey = new char[size_prevkey];
        status = ecall_dh_stage_3_getkey(local_eid, str_prevkey, size_prevkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P0 ecall_dh_stage_3_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 6. get g A p for Party 2;
        // sgx_status_t status = ecall_dh_stage_1(local_eid);
        // if (status != SGX_SUCCESS) {
        //   std::stringstream ss;
        //   ss << "DHKey gen failed, sgx error " << status << ".";
        //   throw std::runtime_error(ss.str());
        // }
        status = ecall_dh_stage_1_parametersize(local_eid, &size_A, &size_p,
                                                &size_g);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey get parametersize failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_A += 1;
        size_p += 1;
        size_g += 1;

        status = ecall_dh_stage_1_getparameter(local_eid, str_A, str_p, str_g,
                                               size_A, size_p, size_g);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey get parameter failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 7. send to p1's ip port str_A,str_p,str_g;
        auto channel1 = grpc::CreateChannel(job_context->next_party,
                                            grpc::InsecureChannelCredentials());
        TransferClient client1(channel1);
        auto sendparamA01ret =
            client1.SendDHParamA(string_A, string_p, string_g, jobid);
        if (!sendparamA01ret.IsOK()) {
          LOG(ERROR) << "Send str_g, str_A, str_p to "
                     << job_context->next_party << " failed, jobid " << jobid
                     << ".";
          setTaskStatus(job_context, task_name, sendparamA01ret);
          continue;
        }

        // 8. recv from p1's port(listen p1's next port),get strB_01
        {
          std::unique_lock<std::mutex> lock(mtx_1);
          cv_1.wait(lock, [job_context, string_B02] {
            return job_context->B != string_B02;
          });  //(job_context->B.c_str() != strB_02)?
        }
        std::cout << "run here: recvB01" << std::endl;
        std::cout << "recvB01: " << job_context->B << std::endl;
        std::string string_B01 = job_context->B;
        memcpy(str_B01, const_cast<char *>(string_B01.c_str()),
               string_B01.size());
        // 9.using recv strB01 to gen next_key
        str_B01[strlen(string_B01.c_str())] = '\0';
        size_t size_B01 = strlen(str_B01) + 1;

        status = ecall_dh_stage_3(local_eid, str_B01, size_B01);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P0 ecall_dh_stage_3 from enclave failed, sgx error " << status
             << ".";
          throw std::runtime_error(ss.str());
        }

        // 10.using B to generate the key.
        status = ecall_dh_stage_3_getkeysize(local_eid, &size_nextkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P0 ecall_dh_stage_3_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_nextkey += 1;
        char *str_nextkey = new char[size_nextkey];
        status = ecall_dh_stage_3_getkey(local_eid, str_nextkey, size_nextkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P0 ecall_dh_stage_3_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        std::cout << "party 0 end" << std::endl;
      } else if (job_context->party_id == 1) {
        size_t size_A, size_p, size_g;
        size_t size_B01, size_B12;
        char str_A[1024], str_p[1024], str_g[1024];
        char str_B01[1024], str_B12[1024];
        // 1. p0,p1 generate and get g,A,p.
        sgx_status_t status = ecall_dh_stage_1(local_eid);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey gen failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }
        status = ecall_dh_stage_1_parametersize(local_eid, &size_A, &size_p,
                                                &size_g);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey get parametersize failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_A += 1;
        size_p += 1;
        size_g += 1;

        status = ecall_dh_stage_1_getparameter(local_eid, str_A, str_p, str_g,
                                               size_A, size_p, size_g);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey get parameter failed, sgx error " << status << ".";
          throw std::runtime_error(ss.str());
        }
        std::string string_A = str_A;
        std::string string_p = str_p;
        std::string string_g = str_g;
        // 2.recv g ,A and p from party 0.
        // recv from p0's port(listen p0's next port)
        {
          std::unique_lock<std::mutex> lock(mtx_1);
          cv_1.wait(lock,
                    [job_context] { return job_context->A.length() != 0; });
        }
        char str_A01[1024], str_p01[1024], str_g01[1024];

        std::string string_A01 = job_context->A;
        std::string string_p01 = job_context->p;
        std::string string_g01 = job_context->g;
        memcpy(str_A01, const_cast<char *>(string_A01.c_str()),
               string_A01.size());
        memcpy(str_p01, const_cast<char *>(string_p01.c_str()),
               string_p01.size());
        memcpy(str_g01, const_cast<char *>(string_g01.c_str()),
               string_g01.size());
        size_t size_A01, size_p01, size_g01;

        // 3.each party using g,A,and p to generate B and one of the key;
        size_A01 = strlen(str_A01) + 1;
        size_p01 = strlen(str_p01) + 1;
        size_g01 = strlen(str_g01) + 1;
        // using str_A,str_p,str_g from p0 to generate B and one of key.
        status = ecall_dh_stage_2(local_eid, str_A01, str_p01, str_g01,
                                  size_A01, size_p01, size_g01);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey g ,a and p f get from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        status = ecall_dh_stage_2_Bsize(local_eid, &size_B01);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_2_Bsize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        size_B01 += 1;
        status = ecall_dh_stage_2_getB(local_eid, str_B01, size_B01);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_2_getB from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 4->10

        // 5. using B to generate the prevkey.
        status = ecall_dh_stage_2_getkeysize(local_eid, &size_prevkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_2_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_prevkey += 1;
        char *str_prevkey = new char[size_prevkey];
        status = ecall_dh_stage_2_getkey(local_eid, str_prevkey, size_prevkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_2_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 6. send to p2's ip port str_A,str_p,str_g;
        auto channel2 = grpc::CreateChannel(job_context->next_party,
                                            grpc::InsecureChannelCredentials());
        TransferClient client2(channel2);
        auto sendparamA12ret =
            client2.SendDHParamA(string_A, string_p, string_g, jobid);
        if (!sendparamA12ret.IsOK()) {
          LOG(ERROR) << "Send str_g, str_A, str_p to "
                     << job_context->next_party << " failed, jobid " << jobid
                     << ".";
          setTaskStatus(job_context, task_name, sendparamA12ret);
          continue;
        }

        // 7.recv from p2's port(listen p2's next port for str_B12
        {
          std::unique_lock<std::mutex> lock(mtx_1);
          cv_1.wait(lock,
                    [job_context] { return job_context->B.length() != 0; });
        }
        std::string string_B12 = job_context->B;
        memcpy(str_B12, const_cast<char *>(string_B12.c_str()),
               string_B12.size());
        str_B12[strlen(string_B12.c_str())] = '\0';
        // 8,using recv strB12 to gen next_key
        size_B12 = strlen(str_B12) + 1;

        status = ecall_dh_stage_3(local_eid, str_B12, size_B12);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_3 from enclave failed, sgx error " << status
             << ".";
          throw std::runtime_error(ss.str());
        }

        status = ecall_dh_stage_3_getkeysize(local_eid, &size_nextkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_3_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_nextkey += 1;
        char *str_nextkey = new char[size_nextkey];
        status = ecall_dh_stage_3_getkey(local_eid, str_nextkey, size_nextkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P1 ecall_dh_stage_3_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 4.send B to party0 for DH exchange.
        std::string string_B = str_B01;
        std::cout << "sendB01: " << string_B << std::endl;
        // send to p0's ip port strB01;
        auto channel1 = grpc::CreateChannel(job_context->prev_party,
                                            grpc::InsecureChannelCredentials());
        TransferClient client1(channel1);
        auto sendparamB01ret = client1.SendDHParamB(string_B, jobid);
        if (!sendparamB01ret.IsOK()) {
          LOG(ERROR) << "Send strB01 seed to " << job_context->prev_party
                     << " failed, jobid " << jobid << ".";
          setTaskStatus(job_context, task_name, sendparamB01ret);
          continue;
        }
        std::cout << "party 1 end." << std::endl;
      } else if (job_context->party_id == 2) {
        // 1.recv g ,A and p from  party 0 .
        size_t size_A02, size_p02, size_g02;
        size_t size_A12, size_p12, size_g12;
        size_t size_B02, size_B12;
        char str_A02[1024], str_p02[1024], str_g02[1024];
        char str_A12[1024], str_p12[1024], str_g12[1024];
        char str_B02[1024], str_B12[1024];

        {
          std::unique_lock<std::mutex> lock(mtx_1);
          cv_1.wait(lock,
                    [job_context] { return job_context->A.length() != 0; });
        }
        std::string string_A02 = job_context->A;
        std::string string_p02 = job_context->p;
        std::string string_g02 = job_context->g;

        char *str_A02_tmp, *str_p02_tmp, *str_g02_tmp;
        str_A02_tmp = const_cast<char *>(string_A02.c_str());
        str_p02_tmp = const_cast<char *>(string_p02.c_str());
        str_g02_tmp = const_cast<char *>(string_g02.c_str());
        std::strncpy(str_A02, str_A02_tmp, strlen(str_A02_tmp));
        std::strncpy(str_p02, str_p02_tmp, strlen(str_p02_tmp));
        std::strncpy(str_g02, str_g02_tmp, strlen(str_g02_tmp));
        str_A02[strlen(str_A02_tmp)] = '\0';
        str_p02[strlen(str_p02_tmp)] = '\0';
        str_g02[strlen(str_g02_tmp)] = '\0';
        size_A02 = strlen(str_A02) + 1;
        size_p02 = strlen(str_p02) + 1;
        size_g02 = strlen(str_g02) + 1;
        // memcpy(str_A02, const_cast<char
        // *>(string_A02.c_str()),string_A02.size()); memcpy(str_p02,
        // const_cast<char *>(string_p02.c_str()),string_p02.size());
        // memcpy(str_g02, const_cast<char
        // *>(string_g02.c_str()),string_g02.size());

        // 2.each party using g,A,and p to generate B and one of the key;
        // size_A02 = strlen(str_A02);
        // size_p02 = strlen(str_p02);
        // size_g02 = strlen(str_g02);

        // using str_A,str_p,str_g from p0 to generate B and one of key.
        status = ecall_dh_stage_2(local_eid, str_A02, str_p02, str_g02,
                                  size_A02, size_p02, size_g02);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey g ,a and p f get from P0 failed, sgx error " << status
             << ".";
          throw std::runtime_error(ss.str());
        }

        status = ecall_dh_stage_2_Bsize(local_eid, &size_B02);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_B02 += 1;
        status = ecall_dh_stage_2_getB(local_eid, str_B02, size_B02);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 3.send  B from each DH exchange.
        std::string string_B02 = str_B02;
        std::cout << "run here: sendB02: " << string_B02 << std::endl;
        // send to p0's ip port strB02;
        auto channel1 = grpc::CreateChannel(job_context->next_party,
                                            grpc::InsecureChannelCredentials());
        TransferClient client1(channel1);
        auto sendparamB02ret = client1.SendDHParamB(string_B02, jobid);
        if (!sendparamB02ret.IsOK()) {
          LOG(ERROR) << "Send str_B02 seed to " << job_context->next_party
                     << " failed, jobid " << jobid << ".";
          setTaskStatus(job_context, task_name, sendparamB02ret);
          continue;
        }

        // 4.using B to generate the key.
        status = ecall_dh_stage_2_getkeysize(local_eid, &size_nextkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_nextkey += 1;
        char *str_nextkey = new char[size_nextkey];
        status = ecall_dh_stage_2_getkey(local_eid, str_nextkey, size_nextkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 5. recv from p1's port(listen p1's next port)
        {
          std::unique_lock<std::mutex> lock(mtx_1);
          cv_1.wait(lock, [job_context] {
            return job_context->A.length() != 0;
          });  //(job_context->A.c_str() != str_A02)
        }

        std::string string_A12 = job_context->A;
        std::string string_p12 = job_context->p;
        std::string string_g12 = job_context->g;
        char *str_A12_tmp, *str_p12_tmp, *str_g12_tmp;
        str_A12_tmp = const_cast<char *>(string_A12.c_str());
        str_p12_tmp = const_cast<char *>(string_p12.c_str());
        str_g12_tmp = const_cast<char *>(string_g12.c_str());
        std::strncpy(str_A12, str_A12_tmp, strlen(str_A12_tmp));
        std::strncpy(str_p12, str_p12_tmp, strlen(str_p12_tmp));
        std::strncpy(str_g12, str_g12_tmp, strlen(str_g12_tmp));
        str_A12[strlen(str_A12_tmp)] = '\0';
        str_p12[strlen(str_p12_tmp)] = '\0';
        str_g12[strlen(str_g12_tmp)] = '\0';
        size_A12 = strlen(str_A12) + 1;
        size_p12 = strlen(str_p12) + 1;
        size_g12 = strlen(str_g12) + 1;

        // 6. using str_A,str_p,str_g from p1 to generate B and one of key.
        status = ecall_dh_stage_2(local_eid, str_A12, str_p12, str_g12,
                                  size_A12, size_p12, size_g12);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "DHKey g ,a and p f get from P1 failed, sgx error " << status
             << ".";
          throw std::runtime_error(ss.str());
        }

        status = ecall_dh_stage_2_Bsize(local_eid, &size_B12);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_B12 += 1;
        status = ecall_dh_stage_2_getB(local_eid, str_B12, size_B12);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkey from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }

        // 7.send and recv B from each DH exchange.
        std::string string_B12 = str_B12;
        std::cout << "run here: sendB12: " << string_B12 << std::endl;
        // send to p1's ip port strB12;
        auto channel2 = grpc::CreateChannel(job_context->prev_party,
                                            grpc::InsecureChannelCredentials());
        TransferClient client2(channel2);
        auto sendparamB12ret = client2.SendDHParamB(string_B12, jobid);
        if (!sendparamB12ret.IsOK()) {
          LOG(ERROR) << "Send str_B12 seed to " << job_context->prev_party
                     << " failed, jobid " << jobid << ".";
          setTaskStatus(job_context, task_name, sendparamB12ret);
          continue;
        }

        // 8. using B to generate the key.
        status = ecall_dh_stage_2_getkeysize(local_eid, &size_prevkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        size_prevkey += 1;
        char *str_prevkey = new char[size_prevkey];
        status = ecall_dh_stage_2_getkey(local_eid, str_prevkey, size_prevkey);
        if (status != SGX_SUCCESS) {
          std::stringstream ss;
          ss << "P2 ecall_dh_stage_2_getkeysize from enclave failed, sgx error "
             << status << ".";
          throw std::runtime_error(ss.str());
        }
        std::cout << "party 2 end." << std::endl;
      }
      setTaskStatus(job_context, task_name, Status::OK());
      LOG(INFO) << "Task " << task_name << " finish, jobid " << jobid << ".";
    } else if (task_name == "StopJob") {
      setTaskStatus(job_context, task_name, Status::OK());
      LOG(WARNING) << "Management thread of job " << jobid
                   << " exit due to stop job task.";
      break;
    } else {
      task_queue.pop();
      Status error = Status::UnavailableError("Unsupported task type");
      setTaskStatus(job_context, task_name, error);
      LOG(ERROR) << "Unsupported task " << task_name << ", jobid " << jobid
                 << ".";
    }
  }
}
}  // namespace smcc
