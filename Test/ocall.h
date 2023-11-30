#pragma once

#include <iostream>
#include <glog/logging.h>

#include "Enclave_u.h"
#include "sgx_urts.h"

void ocall_print_string(const char *str);
