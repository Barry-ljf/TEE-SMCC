#pragma once

#include <glog/logging.h>

#include <iostream>

#include "Enclave_u.h"
#include "sgx_urts.h"

void ocall_print_string(const char *str);
void ocall_print_string(char *str) {
  ocall_print_string(const_cast<const char *>(str));
}