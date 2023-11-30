## Dependence install
------

### Build instruction for openssl in intel sgx
---
This instruction of intel-sgx is based on Ubuntu* 20.04 LTS Server 64bits. For installing intel-sgx in other platform. We can get more details from the git repository  for intel-sgx supported below. 

#### 1.download intel-sgx-ssl package
Use the following command(s) to install the required tools to build the **Intel-SGX SDK**:
```
sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
wget https://github.com/intel/intel-sgx-ssl/archive/refs/tags/lin_2.20_1.1.1u.tar.gz
tar -zxvf lin_2.20_1.1.1u.tar.gz
cd intel-sgx-ssl-lin_2.20_1.1.1u
```
**Note**: To build Intel(R) SGX SDK, gcc version is required to be 7.3 or above and glibc version is required to be 2.27 or above.

Use the following command to install additional required tools and latest Intel(R) SGX SDK Installer to build the **Intel-SGX PSW**
```
sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0
```

Download the source code and prepare the submodules and prebuilt binaries:
```
cd ~
git clone https://github.com/intel/linux-sgx.git
cd linux-sgx && make preparation
```
make sure your https_proxy setting is available, then just wait the download process(maybe many times run `make preparation`)

After downloading the prebuilt binaries, we should copy the mitigation tools corresponding to current OS distribution `external/toolset/{current_distr} \` to `/usr/local/bin \` and make sure they have execute permission, It ensures the updated mitigation tools are used in the later build.

```
sudo cp ~/linux-sgx/external/toolset/{current_distr}/* /usr/local/bin
```
**Note**: The above action is a must even if you copied the previous mitigation tools to /usr/local/bin before. It ensures the updated mitigation tools are used in the later build.

#### 2.download openssl-1.1.1.u package
```
cd ~/intel-sgx-ssl-lin_2.20_1.1.1u/openssl_source
wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1u.tar.gz
tar -zxvf openssl-1.1.1u.tar.gz
```
#### 3.build openssl for intel sgx
```
cd ../Linux
make all
make install
```
After executing the above command without any errors, all header files and library files for OpenSSL will be installed to /opt/intel/sgxssl.

#### 4.build grpc++ for SMCC
Download the grpc source.
The version of grpc downloaded using sudo apt-get is lower, so we need to choose the way to install the source code with a free choice of versions;.
```
git clone https://github.com/grpc/grpc.git 
cd  grpc
git submodule update  --init
git submodule update  --init --recursive //确保库下载完全
cd third_party
git submodule update  --init --recursive 
```
We specifies the compile path for grpc.

```
export MY_INSTALL_DIR=$HOME/.local
```

Switch to the specified version and compile:

```
cd grpc
git checkout v1.15.2
mkdir build && cd build
cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR ..

make -j4
make install
```

