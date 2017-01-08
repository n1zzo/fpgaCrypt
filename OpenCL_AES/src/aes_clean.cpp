#include "mbedtls/aes.h"

#include <utility>
#include <CL/cl.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <iterator>
#include <vector>
#include <array>

#define VERIFY // Enable result comparison with mbedTLS

using namespace std;

const unsigned int key_length = 128;         // Key size in bits
const unsigned int key_size = key_length/8;  // Key size in bytes
const unsigned int ptx_size = 16;            // Plaintext size in bytes

inline void checkErr(cl_int err, const char * name) {
  if (err != CL_SUCCESS) {
    std::cerr << "ERROR: " << name  << " (" << err << ")" << std::endl;
    exit(EXIT_FAILURE);
  }
}

// Compare results with mbedTLS implementation
void mbedEncrypt(const array<unsigned char, ptx_size> &ptx_h,
		 const array<unsigned char, key_size> &key_h,
		 array<unsigned char, ptx_size> &ctx_mbed) {
  mbedtls_aes_context aes_ctx;
  mbedtls_aes_init( &aes_ctx  );
  mbedtls_aes_setkey_enc( &aes_ctx, key_h.data(), key_length );
  mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, ptx_h.data(), ctx_mbed.data() );
  mbedtls_aes_free( &aes_ctx  );
}

int main(void) {
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
  cl::Context context(CL_DEVICE_TYPE_CPU,
                      cprops,
                      NULL,
                      NULL,
                      &err);
  checkErr(err, "Context::Context()");

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

  // Data initialization
  //ptx_h.fill(0x00);
  //ctx_h.fill(0x00);
  //key_h.fill(0x00);

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

  size_t maxWorkGroupSize;
  devices[0].getInfo(CL_DEVICE_MAX_WORK_GROUP_SIZE, &maxWorkGroupSize);
  cout << "Max work group size is: " << maxWorkGroupSize << endl;

  // Open and build kernel
  std::ifstream file("./src/aes_kernel.cl");
  checkErr(file.is_open() ? CL_SUCCESS:-1, "./src/aes_kernel.cl");
  std::string prog(std::istreambuf_iterator<char>(file),
                   (std::istreambuf_iterator<char>()));
  cl::Program::Sources source(1, std::make_pair(prog.c_str(), prog.length()+1));
  cl::Program program(context, source);
  err = program.build(devices,"");
  cout << "Build log: "
       << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(devices[0])
       << endl;
  checkErr(err, "Program::build()");

  cl::Kernel kernel(program, "aesEncrypt", &err);
  checkErr(err, "Kernel::Kernel()");
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
  mbedEncrypt(ptx_h, key_h, ctx_mbed);

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

  return EXIT_SUCCESS;
}
