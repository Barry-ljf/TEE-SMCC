#include <glog/logging.h>
#include <grpcpp/grpcpp.h>

#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "sgx_urts.h"

using namespace std;

void test_gen_seed(sgx_enclave_id_t local_eid) {
  sgx_status_t status = ecall_gen_seed(local_eid);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "Run generate seed failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }
}

void test_rsa(sgx_enclave_id_t local_eid) {
  cout << "-------------RSA--------------" << endl;
  sgx_status_t status = ecall_init_openssl(local_eid);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "init_openssl failed, sgx error " << status << ".";
    LOG(ERROR) << ss.str();
    throw std::runtime_error(ss.str());
  }

  size_t size_n, size_e, size_ctxt;
  char *str_n, *str_e;

  status = ecall_rsa_key_gen(local_eid);

  status = ecall_get_pubkey_size(local_eid, &size_n, &size_e);

  size_n += 1;
  size_e += 1;
  str_n = new char[size_n];
  str_e = new char[size_e];
  status = ecall_get_pubkey(local_eid, str_n, str_e, size_n, size_e);

  cout << "-------------RSA_Enc------------" << endl;
  const char* ptxt =
      "floruitshow!!!!!floruitshow!!!!!floruitshow!!!!!floruitshow!!!!!"
      "floruitshow!!!!!floruitshow!!!!!floruitshow!!!!!floruitshow!!!!!"
      "floruitshow!!!!!floruitshow!!!!!";

  string s = ptxt;
  int l = s.length();
  vector<unsigned char*> ctxt;
  size_ctxt = 128;
  size_ctxt += 1;  //*******
  while (l > 0) {
    char* in = new char[127];
    const char* s1 = (const char*)s.data();
    if (l > 127) {
      strncpy(in, s1, 127);
      s = s.substr(127);
    } else {
      strncpy(in, s1, l + 1);
    }
    l -= 127;
    const char* ptxt_part = (const char*)in;
    cout << "in:   " << ptxt_part << endl;
    unsigned char* ctxt_part;
    size_t size_ptxt = strlen(ptxt_part);
    size_ptxt += 1;
    status = ecall_rsa_enc(local_eid, str_n, str_e, size_n, size_e, ptxt_part,
                           size_ptxt);
    ctxt_part = new unsigned char[128];
    status = ecall_get_ctxt(local_eid, ctxt_part, size_ctxt);
    ctxt.push_back(ctxt_part);
  }
  vector<unsigned char*>::iterator it1;
  it1 = ctxt.begin();
  for (it1; it1 != ctxt.end(); it1++) {
    status = ecall_rsa_ctxt_in(local_eid, *it1, size_ctxt);
    status = ecall_rsa_dec(local_eid);
  }
}
//---------------------------------------------
void test_dh(sgx_enclave_id_t local_eid) {
  sgx_status_t status = ecall_dh_stage_1(local_eid);
  if (status != SGX_SUCCESS) {
    std::stringstream ss;
    ss << "dh failed, sgx error " << status << ".";
    throw std::runtime_error(ss.str());
  }
  size_t size_A, size_p, size_g, size_B, size_key1, size_key2;
  char str_A[1024], str_p[1024], str_g[1024], str_B[1024];

  status = ecall_dh_stage_1_parametersize(local_eid, &size_A, &size_p, &size_g);
  size_A += 1, size_p += 1, size_g += 1;
  status = ecall_dh_stage_1_getparameter(local_eid, str_A, str_p, str_g, size_A,
                                         size_p, size_g);

  status =
      ecall_dh_stage_2(local_eid, str_A, str_p, str_g, size_A, size_p, size_g);

  status = ecall_dh_stage_2_Bsize(local_eid, &size_B);
  size_B += 1;
  status = ecall_dh_stage_2_getB(local_eid, str_B, size_B);

  status = ecall_dh_stage_2_getkeysize(local_eid, &size_key1);
  size_key1 += 1;
  char* str_key1 = new char[size_key1];
  status = ecall_dh_stage_2_getkey(local_eid, str_key1, size_key1);

  status = ecall_dh_stage_3(local_eid, str_B, size_B);

  status = ecall_dh_stage_3_getkeysize(local_eid, &size_key2);
  size_key2 += 1;
  char* str_key2 = new char[size_key2];
  status = ecall_dh_stage_3_getkey(local_eid, str_key2, size_key2);
  if (status == SGX_SUCCESS) {
    std::stringstream ss;
    cout << "Run dh succeed, sgx run done " << endl;
  }
}

int main(void) {
  sgx_enclave_id_t local_eid;
  const char* enclave_path = std::getenv("ENCLAVE_PATH");
  if (enclave_path == nullptr) enclave_path = "../Enclave/Enclave.signed.so";

  sgx_status_t status =
      sgx_create_enclave(enclave_path, 0, NULL, NULL, &local_eid, NULL);
  if (status != SGX_SUCCESS) {
    LOG(ERROR) << "Create enclave failed, sgx error " << status << ".";
    return -1;
  }

  test_gen_seed(local_eid);
  test_rsa(local_eid);
  test_dh(local_eid);
  sgx_destroy_enclave(local_eid);
}
