#sgx settings
SGX_SDK ? = / opt / intel / sgxsdk SGX_MODE
                ? = HW SGX_ARCH ? = x64 SGX_DEBUG ? = 1

                                                    ifeq($(SGX_ARCH), x86)
                                                        SGX_COMMON_CFLAGS
                                                  : = -m32 SGX_LIBRARY_PATH
                                : = $(SGX_SDK) / lib SGX_ENCLAVE_SIGNER
                : = $(SGX_SDK) / bin / x86 / sgx_sign SGX_EDGER8R
        : = $(SGX_SDK) / bin / x86 /
            sgx_edger8r else SGX_COMMON_CFLAGS : = -m64 SGX_LIBRARY_PATH
    : = $(SGX_SDK) / lib64 SGX_ENCLAVE_SIGNER : = $(SGX_SDK) / bin / x64 /
                                                  sgx_sign SGX_EDGER8R
    : = $(SGX_SDK) / bin / x64 /
        sgx_edger8r endif

            ifneq($(SGX_MODE), HW) Urts_Library_Name
    : = sgx_urts_sim else Urts_Library_Name
    : = sgx_urts endif

          CXX = g++ CXXFLAGS += -g - std = c++ 14

      include_path +=
      -I$(SGX_SDK) / include - I / home / ljf /.local / include LDFLAGS +=
      -ldl - lglog

                 PROTOBUF_ABSL_DEPS = absl_absl_check absl_absl_log
          absl_algorithm absl_base absl_bind_front absl_bits absl_btree
              absl_cleanup absl_cord absl_core_headers absl_debugging
                  absl_die_if_null absl_dynamic_annotations absl_flags
                      absl_flat_hash_map absl_flat_hash_set absl_function_ref
                          absl_hash absl_layout absl_log_initialize
                              absl_log_severity absl_memory absl_node_hash_map
                                  absl_node_hash_set absl_optional absl_span
                                      absl_status absl_statusor absl_strings
                                          absl_synchronization absl_time
                                              absl_type_traits absl_utility
                                                  absl_variant

                                                      LDFLAGS +=
      $(SGX_COMMON_CFLAGS) - L$(SGX_LIBRARY_PATH) - l$(Urts_Library_Name) -
              lpthread - L / home / ljf /.local / lib \
		   `pkg -
              config-- libs-- static protobuf grpc++ absl_flags absl_flags_parse
                      $(PROTOBUF_ABSL_DEPS)`

                  Enclave_u.c : @$(SGX_EDGER8R)-- untrusted../
                  Enclave / Enclave.edl-- search -
              path../ Enclave-- search -
              path $(SGX_SDK) / include @echo "GEN  =>  $@"

                                Enclave_u.o : Enclave_u.c @$(CC)
                                                  $(include_path) -
              c $ <
          -o $ @ @echo "CC   <=  $<"

           test : ocall.cc Enclave_u.o test.cc $(CXX) $(CXXFLAGS) $(CPPFLAGS)
                      $ ^
      $(include_path) $(LDFLAGS) -
          o $ @

          clean : @rm -
                  f Enclave_u.*test
