### Build instruction for openssl in intel sgx
#### 1.download intel-sgx-ssl package
```
wget https://github.com/intel/intel-sgx-ssl/archive/refs/tags/lin_2.20_1.1.1u.tar.gz
tar -zxvf lin_2.20_1.1.1u.tar.gz
cd intel-sgx-ssl-lin_2.20_1.1.1u
```
#### 2.download openssl-1.1.1.u package
```
cd openssl_source
wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1u.tar.gz
```
#### 3.build openssl for intel sgx
```
cd ../Linux
make all
make install
```
After executing the above command without any errors, all header files and library files for OpenSSL will be installed to /opt/intel/sgxssl.
