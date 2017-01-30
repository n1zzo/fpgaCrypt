#include "mbedtls/aes.h"
#include "AOCLUtils/aocl_utils.h"

#include <utility>
#include <CL/cl2.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <iterator>
#include <vector>
#include <array>
#include <assert.h>

#define VERIFY    // Enable result comparison with mbedTLS

#define INTELFPGA // External Kernel compilation

#ifndef INTELFPGA
#define STDOPENCL // Standard OpenCl Kernel compilation
#endif // INTELFPGA

using namespace std;
using namespace aocl_utils;

const unsigned int key_length = 128;         // Key size in bits
const unsigned int key_size = key_length/8;  // Key size in bytes
const unsigned int ptx_size = 16;            // Plaintext size in bytes
const size_t ptx_size_xts = 1024;	     // XTS Plaintext size in bytes

const char *getErrorString(cl_int error);

// Cleanup code used by aocl_utils
void cleanup() {
  ;
}

inline void checkErr(cl_int err, const char * name) {
  if (err != CL_SUCCESS) {
    std::cerr << "ERROR: " << name  << " (" << getErrorString(err) << ")" << std::endl;
    exit(EXIT_FAILURE);
  }
}

// Compare results with mbedTLS implementation
void mbedAesReference(const array<unsigned char, ptx_size> &ptx_h,
		      const array<unsigned char, key_size> &key_h,
		      array<unsigned char, ptx_size> &ctx_mbed) {
  mbedtls_aes_context aes_ctx;
  mbedtls_aes_init( &aes_ctx  );
  mbedtls_aes_setkey_enc( &aes_ctx, key_h.data(), key_length );
  mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, ptx_h.data(), ctx_mbed.data() );
  mbedtls_aes_free( &aes_ctx  );
}

void mbedXtsReference(const vector<unsigned char> &ptx_h,
		      const vector<unsigned char> &key_h,
                      vector<unsigned char> &iv_h,
		      vector<unsigned char> &ctx_mbed) {
  // key_len is expressed in bytes, data_len in bits
  int key_len, data_len;

  mbedtls_aes_context crypt_ctx, tweak_ctx;
  mbedtls_aes_init( &crypt_ctx  );
  mbedtls_aes_init( &tweak_ctx  );
  
  key_len = key_h.size();
  data_len = ptx_h.size();

  mbedtls_aes_setkey_enc( &crypt_ctx, key_h.data(), (key_len*8)/2);
  mbedtls_aes_setkey_enc( &tweak_ctx, key_h.data()+(key_len/2), (key_len*8)/2);
  mbedtls_aes_crypt_xts( &crypt_ctx, &tweak_ctx, MBEDTLS_AES_ENCRYPT,
                         data_len, iv_h.data(),
                         ptx_h.data(), ctx_mbed.data() );
  mbedtls_aes_free( &crypt_ctx  );
  mbedtls_aes_free( &tweak_ctx  );
}

cl::Context initOpenclPlatform() {
  // Opencl Device introspection
  cl_int err;
  vector< cl::Platform > platformList;
  cl::Platform::get(&platformList);
  checkErr(platformList.size()!=0 ? CL_SUCCESS : -1, "cl::Platform::get");
  std::cerr << "Platform number is: " << platformList.size() << std::endl;
  std::string platformInfo;
  platformList[0].getInfo((cl_platform_info)CL_PLATFORM_EXTENSIONS, &platformInfo);
  std::cerr << "Platform extensions: " << platformInfo << "\n";
  platformList[0].getInfo((cl_platform_info)CL_PLATFORM_NAME, &platformInfo);
  std::cerr << "Platform name: " << platformInfo << "\n";
  platformList[0].getInfo((cl_platform_info)CL_PLATFORM_PROFILE, &platformInfo);
  std::cerr << "Platform profile: " << platformInfo << "\n";
  platformList[0].getInfo((cl_platform_info)CL_PLATFORM_VENDOR, &platformInfo);
  std::cerr << "Platform vendor: " << platformInfo << "\n";
  platformList[0].getInfo((cl_platform_info)CL_PLATFORM_VERSION, &platformInfo);
  std::cerr << "Platform version: " << platformInfo << "\n";
  cl_context_properties cprops[3] = {CL_CONTEXT_PLATFORM, (cl_context_properties)(platformList[0])(), 0};
  cl::Context context(CL_DEVICE_TYPE_ALL,
                      cprops,
                      NULL,
                      NULL,
                      &err);
  checkErr(err, "Context::Context()");
  return context;
}

cl::Kernel createOpenClKernel(const cl::Context &context,
                              const vector<cl::Device> &devices,
                              const string &sourcePath,
                              const string &kernelName) {
  cl_int err;



  size_t maxWorkGroupSize;
  devices[0].getInfo(CL_DEVICE_MAX_WORK_GROUP_SIZE, &maxWorkGroupSize);
  cout << "Max work group size is: " << maxWorkGroupSize << endl;

  #ifdef STDOPENCL
    // Open and build kernel
    std::ifstream file(sourcePath);
    checkErr(file.is_open() ? CL_SUCCESS:-1, sourcePath);
    std::string prog(std::istreambuf_iterator<char>(file),
                     (std::istreambuf_iterator<char>()));
    cl::Program::Sources source(1, std::make_pair(prog.c_str(), prog.length()+1));
    cl::Program program(context, source);
    err = program.build(devices,"");
    cout << "Build log: "
         << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(devices[0])
         << endl;
    checkErr(err, "Program::build()");
  #endif // STDOPENCL

  #ifdef INTELFPGA
    // Create the program
    string binary_file = getBoardBinaryFile(sourcePath.c_str(), devices[0]());
    printf("Using AOCX: %s\n", binary_file.c_str());
    cl_program p = createProgramFromBinary(context(), binary_file.c_str(), &(devices[0]()), 1);
    cl::Program program = cl::Program(p, false);
  #endif // INTELFPGA

  cl::Kernel kernel(program, kernelName.c_str(), &err);
  checkErr(err, "Kernel::Kernel()");

  return kernel;
}

void aes_test() {
  cl_int err;

  // Initialize opencl board
  cl::Context context = initOpenclPlatform();

  // Buffer creation
  array<unsigned char, ptx_size> ptx_h = {0x32, 0x43, 0xf6, 0xa8,
                                          0x88, 0x5a, 0x30, 0x8d,
                                          0x31, 0x31, 0x98, 0xa2,
                                          0xe0, 0x37, 0x07, 0x34};
  array<unsigned char, ptx_size> ctx_h;
  array<unsigned char, key_size> key_h = {0x2b, 0x7e, 0x15, 0x16,
                                          0x28, 0xae, 0xd2, 0xa6,
                                          0xab, 0xf7, 0x15, 0x88,
                                          0x09, 0xcf, 0x4f, 0x3c};

  cl::Buffer ptxBuffer(context,
                       CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                       ptx_size,
                       ptx_h.data(),
                       &err);
                       checkErr(err, "Buffer::Buffer()");

  cl::Buffer ctxBuffer(context,
                       CL_MEM_WRITE_ONLY | CL_MEM_USE_HOST_PTR,
                       ptx_size,
                       ctx_h.data(),
                       &err);
                       checkErr(err, "Buffer::Buffer()");

  cl::Buffer keyBuffer(context,
                       CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                       key_size,
                       key_h.data(),
                       &err);
                       checkErr(err, "Buffer::Buffer()");

  // Get devices from context
  vector<cl::Device> devices;
  devices = context.getInfo<CL_CONTEXT_DEVICES>();
  checkErr(devices.size() > 0 ? CL_SUCCESS : -1, "devices.size() > 0");

  cl::Kernel kernel = createOpenClKernel(context,
                                         devices,
                                         "./aes_kernel",
                                         "aesEncrypt");

  err = kernel.setArg(0, ptxBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(1, keyBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(2, ctxBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(3, key_length);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(4, ptx_size);
  checkErr(err, "Kernel::setArg()");

  // Create command queue and run kernel
  cl::CommandQueue queue(context, devices[0], 0, &err);
  checkErr(err, "CommandQueue::CommandQueue()");cl::Event event;
  err = queue.enqueueNDRangeKernel(kernel,
                                   cl::NullRange,
                                   cl::NDRange(4),
                                   cl::NDRange(4),
                                   NULL,
                                   &event);
  checkErr(err, "ComamndQueue::enqueueNDRangeKernel()");

  // Read results from device
  event.wait();
  err = queue.enqueueReadBuffer(ctxBuffer,
                                CL_TRUE,
                                0,
                                ptx_size,
                                ctx_h.data());
  checkErr(err, "ComamndQueue::enqueueReadBuffer()");

  // Print results
  cout << "Key is:                ";
  for(uint i = 0; i < key_size; i++) {
    printf("%02X", key_h[i]);
  }
  cout << endl << "Plaintext is:          ";
  for(uint i = 0; i < ptx_size; i++) {
    printf("%02X", ptx_h[i]);
  }
  cout << endl << "Ciphertext is:         ";
  for(uint i = 0; i < ptx_size; i++) {
    printf("%02X", ctx_h[i]);
  }
  cout << endl;

  #ifdef VERIFY
  // Compare results
  array<unsigned char, ptx_size> ctx_mbed;
  mbedAesReference(ptx_h, key_h, ctx_mbed);

  cout << "MbedTLS ciphertext is: ";
  for(uint i = 0; i < ptx_size; i++) {
    printf("%02X", ctx_mbed[i]);
  }
  cout << endl;

  if (ctx_h == ctx_mbed)
    cout << "CORRECT: the ciphertexts match!" << endl;
  else
    cout << "WRONG: the ciphertexts do not match!" << endl;
  #endif //VERIFY

}

void xts_test() {

	
  // Define the key, plaintext, blocks number
  vector<unsigned char> ptx_h;
  vector<unsigned char> key_h;
  vector<unsigned char> ctx_h;

  ptx_h.resize(ptx_size_xts);
  key_h.resize(key_size * 2);
  ctx_h.resize(ptx_size_xts);

  ifstream urandom("/dev/urandom", ios::in|ios::binary);
  assert(urandom.good());
  urandom.read(reinterpret_cast<char*>(ptx_h.data()), ptx_size_xts);
  urandom.read(reinterpret_cast<char*>(key_h.data()), key_size * 2);
  assert(urandom.good());
  urandom.close(); 

  cout << endl << "Plaintext: " << endl;
  for(uint i = 0; i < ptx_size_xts; i++) {
    printf("%02X", ptx_h[i]);
  }
  cout << endl << "Key: " << endl;
  for(uint i = 0; i < key_size * 2; i++) {
    printf("%02X", key_h[i]);
  }
  cout << endl << "Ciphertext: " << endl;
  for(uint i = 0; i < ptx_size_xts; i++) {
    printf("%02X", ctx_h[i]);
  }

  // Compute sequentially the tweaks for each block
  // Spawn aes-xts kernels and feed them with blocks
  // Compute last round and perform ctx stealing
}

int main(int argc, char *argv[]) {
  //aes_test();
  xts_test();
}
