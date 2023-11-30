#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cstdio>
#include <map>
#include <queue>
#include <random>
#include <string>

#include "Enclave_t.h"
#include "PRNG.h"
#include "sgx_trts.h"
#include "sgx_urts.h"

#define MAX_BUF_LEN 100

static const unsigned char gcm_iv[] = {0x99, 0xaa, 0x3e, 0x68,
                                       0xed, 0x81, 0x73, 0xa0};

static const unsigned char gcm_aad[] = {0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34,
                                        0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
                                        0x7f, 0xec, 0x78, 0xde};

typedef __int128_t int128_t;
typedef struct {
  char *str_e;
  char *str_d;
  char *str_n;
} RsaKey;

typedef struct {
  uint64_t nextseed;
  uint64_t prevseed;
  sgx_enclave_id_t eid;
  std::queue<int128_t> zero_share;

  // RSS of all data provider.
  std::map<std::string, std::vector<int128_t>> datasets;

  // For DH algorithm.
  char str_A[1024];
  char str_a[1024];
  char str_B[1024];
  char str_b[1024];
  char str_p[1024];
  char str_q[1024];
  char str_g[1024];

  unsigned char dh_key[32];
  unsigned char dh_key2[32];
  // For the construction of secure share.
  PRNG mNextCommon, mPrevCommon, mCommon;
  uint64_t mShareIdx = 0, mShareGenIdx = 0;
  std::array<AES, 2> mShareGen;
  std::array<std::vector<block>, 2> mShareBuff;

  // For RSA algorithm and this instance saves memory allocated from heap.
  RsaKey rsa_key;
} Context2;

Context2 tee_context;

unsigned char *ctxt;
unsigned char *ctxt_in;

void ecall_init_openssl() { OPENSSL_init_crypto(0, NULL); }

void ecall_rsa_key_gen() {
  RSA *r;
  r = RSA_new();
  int bits = 1024;

  BIGNUM *bne;
  bne = BN_new();
  BN_set_word(bne, RSA_F4);
  RSA_generate_key_ex(r, bits, bne, NULL);

  const BIGNUM *n, *e, *d;
  RSA_get0_key(r, &n, &e, &d);

  tee_context.rsa_key.str_n = BN_bn2hex(n);
  tee_context.rsa_key.str_d = BN_bn2hex(d);
  tee_context.rsa_key.str_e = BN_bn2hex(e);
}
void ecall_get_pubkey_size(size_t *size_n, size_t *size_e) {
  *size_n = strlen(tee_context.rsa_key.str_n);
  *size_e = strlen(tee_context.rsa_key.str_e);
}
void ecall_get_pubkey(char *str_n, char *str_e, size_t size_n, size_t size_e) {
  memcpy(str_n, tee_context.rsa_key.str_n,
         strlen(tee_context.rsa_key.str_n) + 1);
  memcpy(str_e, tee_context.rsa_key.str_e,
         strlen(tee_context.rsa_key.str_e) + 1);
}
void ecall_rsa_enc(char *str_n, char *str_e, size_t size_n, size_t size_e,
                   const char *ptxt, size_t size_ptxt) {
  RSA *r;
  r = RSA_new();
  int flen;
  BIGNUM *bnn, *bne;

  const unsigned char *in = (const unsigned char *)ptxt;

  unsigned char *out;

  bnn = BN_new();
  bne = BN_new();
  // bnd = BN_new();
  BN_hex2bn(&bnn, str_n);
  BN_hex2bn(&bne, str_e);
  // BN_hex2bn(&bnd, hexd0);
  RSA_set0_key(r, bnn, bne, NULL);
  flen = RSA_size(r);
  out = (unsigned char *)malloc(flen * 2);
  ctxt = (unsigned char *)malloc(flen * 2);
  ctxt_in = (unsigned char *)malloc(flen * 2);
  bzero(out, flen);

  RSA_public_encrypt(flen, in, out, r, RSA_NO_PADDING);
  memcpy(ctxt, out, flen + 1);
  RSA_free(r);

  return;
}

void ecall_get_ctxt(unsigned char *ctxt_out, size_t size_ctxt) {
  memcpy(ctxt_out, ctxt, size_ctxt);
}
void ecall_rsa_ctxt_in(unsigned char *ctxt_part, size_t size_ctxt_part) {
  memcpy(ctxt_in, ctxt_part, size_ctxt_part);
}
void ecall_rsa_dec() {
  BIGNUM *bnn, *bne, *bnd;

  bnn = BN_new();
  bne = BN_new();
  bnd = BN_new();
  BN_hex2bn(&bnn, tee_context.rsa_key.str_n);
  BN_set_word(bne, RSA_F4);
  BN_hex2bn(&bnd, tee_context.rsa_key.str_d);

  RSA *r;
  r = RSA_new();
  RSA_set0_key(r, bnn, bne, bnd);

  int flen = RSA_size(r);
  unsigned char *ptxt_part;
  ptxt_part = new unsigned char[flen + 1];
  bzero(ptxt_part, flen);
  RSA_private_decrypt(flen, ctxt_in, ptxt_part, r, RSA_NO_PADDING);
  char *s = (char *)ptxt_part;
  ocall_print_string(s);
  RSA_free(r);
  return;
}

void ecall_dh_stage_1() {
  DH *party1 = NULL;
  const BIGNUM *A = NULL, *p = NULL, *g = NULL, *a = NULL;
  // p = BN_new();
  int i;

  party1 = DH_new();
  DH_generate_parameters_ex(party1, 128, DH_GENERATOR_2, NULL);
  DH_check(party1, &i);
  DH_get0_pqg(party1, &p, NULL, &g);

  char *sp, *sg, *sa, *sA;
  DH_generate_key(party1);
  DH_get0_key(party1, &A, &a);

  sp = BN_bn2hex(p);
  sg = BN_bn2hex(g);
  sA = BN_bn2hex(A);
  sa = BN_bn2hex(a);
  memcpy(tee_context.str_g, sg, strlen(sg));
  memcpy(tee_context.str_p, sp, strlen(sp));
  memcpy(tee_context.str_a, sa, strlen(sa));
  memcpy(tee_context.str_A, sA, strlen(sA));

  DH_free(party1);
}
void ecall_dh_stage_1_parametersize(size_t *size_A, size_t *size_p,
                                    size_t *size_g) {
  *size_A = strlen(tee_context.str_A);
  *size_p = strlen(tee_context.str_p);
  *size_g = strlen(tee_context.str_g);
}

void ecall_dh_stage_1_getparameter(char *str_A, char *str_p, char *str_g,
                                   size_t size_A, size_t size_p,
                                   size_t size_g) {
  memcpy(str_A, tee_context.str_A, strlen(tee_context.str_A) + 1);
  memcpy(str_p, tee_context.str_p, strlen(tee_context.str_p) + 1);
  memcpy(str_g, tee_context.str_g, strlen(tee_context.str_g) + 1);
}

void ecall_dh_stage_2(char *str_A, char *str_p, char *str_g, size_t size_A,
                      size_t size_p, size_t size_g) {
  const BIGNUM *B = NULL, *b = NULL;

  char *sp, *sg, *sA, *sB;
  ocall_print_string(str_A);
  ocall_print_string(str_p);
  ocall_print_string(str_g);
  sp = new char[size_p];
  sg = new char[size_g];
  sA = new char[size_A];
  sB = new char[1024];
  memcpy(sp, str_p, size_p);
  memcpy(sg, str_g, size_g);
  memcpy(sA, str_A, size_A);

  BIGNUM *p = BN_new();
  BIGNUM *g = BN_new();
  BIGNUM *A = BN_new();

  BN_hex2bn(&p, sp);
  BN_hex2bn(&g, sg);
  BN_hex2bn(&A, sA);

  int i;
  DH *party2 = NULL;
  party2 = DH_new();

  DH_generate_parameters_ex(party2, 128, DH_GENERATOR_2, NULL);
  DH_check(party2, &i);
  DH_set0_pqg(party2, p, NULL, g);
  DH_generate_key(party2);
  DH_get0_key(party2, &B, &b);
  sB = BN_bn2hex(B);

  memcpy(tee_context.str_B, sB, strlen(sB) + 1);

  unsigned char *bbuf = (unsigned char *)OPENSSL_malloc(DH_size(party2));
  DH_compute_key(bbuf, A, party2);
  // char*s=(char*)bbuf;
  memcpy(tee_context.dh_key, bbuf, 16);

  DH_free(party2);
  free(sp);
  free(sg);
  free(sA);
  free(sB);
}

void ecall_dh_stage_2_Bsize(size_t *size_B) {
  *size_B = strlen(tee_context.str_B);
}
void ecall_dh_stage_2_getB(char *str_B, size_t size_B) {
  memcpy(str_B, tee_context.str_B, strlen(tee_context.str_B) + 1);
}
void ecall_dh_stage_2_getkeysize(size_t *size_key) {
  char *s = (char *)tee_context.dh_key;
  *size_key = strlen(s);
}
void ecall_dh_stage_2_getkey(char *str_key, size_t size_key) {
  memcpy(str_key, tee_context.dh_key, size_key);
}
void ecall_dh_stage_3(char *str_B, size_t size_B) {
  char *pstr, *gstr, *astr, *Bstr;
  const BIGNUM *apubkey, *aprivkey;

  pstr = tee_context.str_p;
  gstr = tee_context.str_g;
  astr = tee_context.str_a;
  Bstr = str_B;
  ocall_print_string(str_B);
  int i;
  BIGNUM *p = BN_new();
  BIGNUM *g = BN_new();
  BIGNUM *a = BN_new();
  BIGNUM *B = BN_new();

  BN_hex2bn(&p, pstr);
  BN_hex2bn(&g, gstr);
  BN_hex2bn(&a, astr);
  BN_hex2bn(&B, Bstr);

  DH *party1 = NULL;
  party1 = DH_new();

  DH_generate_parameters_ex(party1, 128, DH_GENERATOR_2, NULL);
  DH_check(party1, &i);
  DH_set0_pqg(party1, p, NULL, g);
  DH_generate_key(party1);
  DH_get0_key(party1, &apubkey, &aprivkey);
  DH_set0_key(party1, NULL, a);

  unsigned char *abuf = (unsigned char *)OPENSSL_malloc(DH_size(party1));
  DH_compute_key(abuf, B, party1);
  // char*s=(char*)abuf;
  memcpy(tee_context.dh_key2, abuf, 16);
  DH_free(party1);
  return;
}
void ecall_dh_stage_3_getkeysize(size_t *size_key) {
  char *s = (char *)tee_context.dh_key2;
  *size_key = strlen(s);
}
void ecall_dh_stage_3_getkey(char *str_key, size_t size_key) {
  memcpy(str_key, tee_context.dh_key2, size_key);
}
unsigned char *aes_gcm_enc(const char *plaintext, int length,
                           unsigned char *tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
  // Set IV length if default 96 bits is not appropriate
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), nullptr);
  // Initialise key and IV
  EVP_EncryptInit_ex(ctx, nullptr, nullptr, tee_context.dh_key, gcm_iv);
  // Zero or more calls to specify any AAD
  int outlen;
  EVP_EncryptUpdate(ctx, nullptr, &outlen, gcm_aad, sizeof(gcm_aad));
  unsigned char outbuf[1024];
  // Encrypt plaintext
  EVP_EncryptUpdate(ctx, outbuf, &outlen, (const unsigned char *)plaintext,
                    strlen(plaintext));
  length = outlen;
  unsigned char *ciphertext = new unsigned char[length];

  // memcpy(ciphertext.get(), outbuf, length);
  for (int i = 0; i < length; i++) {
    ciphertext[i] = outbuf[i];
  }
  // Finalise: note get no output for GCM
  EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
  // Get tag
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
  memcpy(tag, outbuf, 16);
  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext;
}

unsigned char *aes_gcm_dec(const unsigned char *ciphertext, int &length,
                           const unsigned char *tag) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // Select cipher
  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
  // Set IV length, omit for 96 bits
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), nullptr);
  // Specify key and IV
  EVP_DecryptInit_ex(ctx, nullptr, nullptr, tee_context.dh_key, gcm_iv);
  int outlen;
  // Zero or more calls to specify any AAD
  EVP_DecryptUpdate(ctx, nullptr, &outlen, gcm_aad, sizeof(gcm_aad));
  unsigned char outbuf[1024];
  // Decrypt plaintext
  EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, length);
  // Output decrypted block
  length = outlen;

  unsigned char *plaintext = new unsigned char[length];

  for (int i = 0; i < length; i++) {
    plaintext[i] = outbuf[i];
  }
  // Set expected tag value
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag);
  // Finalise: note get no output for GCM
  // int rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
  EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
  // Print out return value. If this is not successful authentication failed and
  // plaintext is not trustworthy.
  // fprintf(stdout, "Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
  EVP_CIPHER_CTX_free(ctx);
  return plaintext;
}

void ecall_gen_seed() {
  sgx_read_rand(reinterpret_cast<uint8_t *>(&(tee_context.nextseed)),
                sizeof(uint64_t));
}

void ecall_get_nextSeed(uint64_t *ret_ptr, size_t output_size) {
  // encrypt nextSeed and return
  *ret_ptr = tee_context.nextseed;
}

void ecall_set_prevSeed(uint64_t seed) {
  // decrypt and save
  tee_context.prevseed = seed;
}

void ecall_AES_generate(uint64_t buffSize = 256) {
  tee_context.mCommon.SetSeed(toBlock(3488535245, 2454523));
  tee_context.mNextCommon.SetSeed(
      toBlock(tee_context.nextseed));  // nextSeed is from local parameter
  tee_context.mPrevCommon.SetSeed(
      toBlock(tee_context.prevseed));  // precvSeed is from another party

  tee_context.mShareGenIdx = 0;
  tee_context.mShareBuff[0].resize(buffSize);
  tee_context.mShareBuff[1].resize(buffSize);

  tee_context.mShareGen[0].setKey(tee_context.mPrevCommon.get());
  tee_context.mShareGen[1].setKey(tee_context.mNextCommon.get());

  // refillBuffer();
  tee_context.mShareGen[0].ecbEncCounterMode(tee_context.mShareGenIdx,
                                             tee_context.mShareBuff[0].size(),
                                             tee_context.mShareBuff[0].data());
  tee_context.mShareGen[1].ecbEncCounterMode(tee_context.mShareGenIdx,
                                             tee_context.mShareBuff[1].size(),
                                             tee_context.mShareBuff[1].data());
  tee_context.mShareGenIdx += tee_context.mShareBuff[0].size();
  tee_context.mShareIdx = 0;
}

int128_t ecall_get_share(int128_t val = 0) {
  if (tee_context.mShareIdx + sizeof(int64_t) >
      tee_context.mShareBuff[0].size() * sizeof(block)) {
    // refillBuffer();
    tee_context.mShareGen[0].ecbEncCounterMode(
        tee_context.mShareGenIdx, tee_context.mShareBuff[0].size(),
        tee_context.mShareBuff[0].data());

    tee_context.mShareGen[1].ecbEncCounterMode(
        tee_context.mShareGenIdx, tee_context.mShareBuff[1].size(),
        tee_context.mShareBuff[1].data());

    tee_context.mShareGenIdx += tee_context.mShareBuff[0].size();
    tee_context.mShareIdx = 0;
  }

  // ret is share part
  int128_t ret =
      *reinterpret_cast<uint64_t *>(
          reinterpret_cast<uint8_t *>(tee_context.mShareBuff[0].data()) +
          tee_context.mShareIdx) -
      *reinterpret_cast<uint64_t *>(
          reinterpret_cast<uint8_t *>(tee_context.mShareBuff[1].data()) +
          tee_context.mShareIdx);

  tee_context.mShareIdx += sizeof(int64_t);
  tee_context.zero_share.push(ret + val);
  return ret + val;
}

si128 i128_add(si128 A, si128 B) {
  struct si128 ret;
  ret.mData[0] = A.mData[0] + B.mData[0];
  ret.mData[1] = A.mData[1] + B.mData[1];
  return ret;
}

int128_t i128_mul(si128 A, si128 B) {
  int128_t C = A.mData[0] * B.mData[0] + A.mData[0] * B.mData[1] +
               A.mData[1] * B.mData[0] + ecall_get_share(0);
  return C;
}

int128_t reveal(int128_t A, int128_t B, int128_t C) { return A + B + C; }
