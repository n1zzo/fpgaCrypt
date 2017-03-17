#include "mbedtls/aes.h"
#include "AOCLUtils/aocl_utils.h"

#include <utility>
#include <CL/cl2.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <iterator>
#include <vector>
#include <assert.h>

#define VERIFY    // Enable result comparison with mbedTLS

#define INTELFPGA // External Kernel compilation

#ifndef INTELFPGA
#define STDOPENCL // Standard OpenCl Kernel compilation
#endif // INTELFPGA

#define AES_BLK_BYTES 16 // AES block size
#define GF_128_FDBK 0x87 // Modulus of the Galois Field

using namespace std;
using namespace aocl_utils;

const unsigned int xts_key_size = 16;        // Key size in bytes
const unsigned int iv_size = AES_BLK_BYTES;  // XTS IV size (1 cipher block)
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
void mbedAesReference(const vector<unsigned char> &ptx_h,
                      const vector<unsigned char> &key_h,
                      vector<unsigned char> &ctx_mbed) {
  mbedtls_aes_context aes_ctx;
  mbedtls_aes_init( &aes_ctx  );
  mbedtls_aes_setkey_enc( &aes_ctx, key_h.data(), key_h.size()*8 );
  mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, ptx_h.data(), ctx_mbed.data() );
  mbedtls_aes_free( &aes_ctx  );
}

void mbedXtsReference(const vector<unsigned char> &ptx_h,
                      const vector<unsigned char> &key_h,
                      vector<unsigned char> &iv_h,
                      vector<unsigned char> &ctx_mbed) {
  // key_len is expressed in bytes, data_len in bits
  int key_len, data_len_bits;

  mbedtls_aes_context crypt_ctx, tweak_ctx;
  mbedtls_aes_init( &crypt_ctx  );
  mbedtls_aes_init( &tweak_ctx  );

  key_len = key_h.size();
  data_len_bits = ptx_h.size()*8;

  mbedtls_aes_setkey_enc( &crypt_ctx, key_h.data(), (key_len*8)/2);
  mbedtls_aes_setkey_enc( &tweak_ctx, key_h.data()+(key_len/2), (key_len*8)/2);

  mbedtls_aes_crypt_xts( &crypt_ctx, &tweak_ctx, MBEDTLS_AES_ENCRYPT,
      data_len_bits, iv_h.data(),
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
  cl_bool deviceEndianLittle;

  devices[0].getInfo(CL_DEVICE_MAX_WORK_GROUP_SIZE, &maxWorkGroupSize);
  cout << endl << "Max work group size is: " << maxWorkGroupSize << endl;
  devices[0].getInfo(CL_DEVICE_ENDIAN_LITTLE, &deviceEndianLittle);
  if(deviceEndianLittle)
    cout << "Device is little-endian." << endl;
  else
    cout << "Device is big-endian." << endl;

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

void opencl_aes_crypt_ecb(vector<unsigned char> &ptx_h,
                          vector<unsigned char> &key_h,
                          vector<unsigned char> &ctx_h) {

  // Verify key size is one of the supported ones
  int key_size_bits = key_h.size() * 8;
  if(key_size_bits != 128 && key_size_bits != 192 && key_size_bits != 256) {
    cerr << "Error: unsupported key size -> " << key_size_bits << endl;
    exit(-1);
  }

  cl_int err;

  // Initialize opencl board
  cl::Context context = initOpenclPlatform();

  cl::Buffer ptxBuffer(context, ptx_h.begin(), ptx_h.end(), true, true, &err);
  checkErr(err, "Buffer::Buffer()");

  cl::Buffer ctxBuffer(context, ctx_h.begin(), ctx_h.end(), false, true, &err);
  checkErr(err, "Buffer::Buffer()");

  cl::Buffer keyBuffer(context, key_h.begin(), key_h.end(), true, true, &err);
  checkErr(err, "Buffer::Buffer()");

  // Get devices from context
  vector<cl::Device> devices;
  devices = context.getInfo<CL_CONTEXT_DEVICES>();
  checkErr(devices.size() > 0 ? CL_SUCCESS : -1, "devices.size() > 0");

  cl::Kernel kernel = createOpenClKernel(context,
      devices,
      "./aes_kernel",
      "aesEncrypt");

  int ptx_size = ptx_h.size();

  err = kernel.setArg(0, ptxBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(1, keyBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(2, ctxBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(3, key_size_bits);
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
  checkErr(err, "CommandQueue::enqueueNDRangeKernel()");

  // Read results from device
  event.wait();
  err = queue.enqueueReadBuffer(ctxBuffer,
      CL_TRUE,
      0,
      ctx_h.size(),
      ctx_h.data());
  checkErr(err, "CommandQueue::enqueueReadBuffer()");
}

void aes_test() {

  // Buffer creation
  vector<unsigned char> ptx_h = {0x32, 0x43, 0xf6, 0xa8,
                                 0x88, 0x5a, 0x30, 0x8d,
                                 0x31, 0x31, 0x98, 0xa2,
                                 0xe0, 0x37, 0x07, 0x34};
  vector<unsigned char> ctx_h = {0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00};
  vector<unsigned char> key_h = {0x2b, 0x7e, 0x15, 0x16,
                                 0x28, 0xae, 0xd2, 0xa6,
                                 0xab, 0xf7, 0x15, 0x88,
                                 0x09, 0xcf, 0x4f, 0x3c};

  opencl_aes_crypt_ecb(ptx_h, key_h, ctx_h);

  // Print results
  cout << endl << "Key is:                ";
  for(const unsigned char &byte : key_h)
    cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  cout << endl << "Plaintext is:          ";
  for(const unsigned char &byte : ptx_h)
    cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  cout << endl << "Ciphertext is:         ";
  for(const unsigned char &byte : ctx_h)
    cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);

#ifdef VERIFY
  vector<unsigned char> ctx_mbed = {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

  // Compare results
  mbedAesReference(ptx_h, key_h, ctx_mbed);

  cout << endl << "MbedTLS ciphertext is: ";
  for(const unsigned char &byte : ctx_mbed)
    cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  cout << endl;

  if (ctx_h == ctx_mbed)
    cout << "CORRECT: the ciphertexts match!" << endl;
  else
    cout << "WRONG: the ciphertexts DO NOT match!" << endl;
#endif //VERIFY

}

void gf128_tweak_mult(unsigned char tweak[]) {
  // Galois Field modular multiplication over GF(2) modulo
  // x^128 + x^7 + x^2 + x + 1, with 2 primitive element of GF(2^128)
   
  int carry_out, carry_in = 0; 
  for (int j = 0; j < AES_BLK_BYTES; j++) {
    carry_out = (tweak[j] >> 7) & 1;
    tweak[j] = ((tweak[j] << 1) + carry_in) & 0xFF;
    carry_in = carry_out;
  }
  if (carry_out)
    tweak[0] ^= GF_128_FDBK;
}

void opencl_aes_crypt_xts(vector<unsigned char> &ptx_h,
                          vector<unsigned char> &key_h,
                          vector<unsigned char> &iv_h,
                          vector<unsigned char> &ctx_h) {

  // Verify plaintext size is greater than 16 Byte
  if(ptx_h.size() < 16) {
    cerr << "Error: plaintext is too short, cannot perform ciphertext stealing!"
         << endl;
    exit(-1);
  }

  int nblocks = ptx_h.size() / 16;

  vector<unsigned char> key1(key_h.begin(), key_h.begin()+(key_h.size()/2));
  vector<unsigned char> key2(key_h.begin()+(key_h.size()/2), key_h.end());
  // Tweak size is equal to the plaintext size
  vector<unsigned char> tweak(ptx_h.size(), 0);

  // Compute initial tweak value
  opencl_aes_crypt_ecb(iv_h, key2, tweak);
  
  // Fill tweak vector
  for(int i = AES_BLK_BYTES; i < nblocks*AES_BLK_BYTES; i++) {
    tweak[i] = tweak[i-AES_BLK_BYTES];
    if(i%AES_BLK_BYTES == (AES_BLK_BYTES-1))
      gf128_tweak_mult(tweak.data()+(i-(AES_BLK_BYTES-1)));
  }

  cout << endl << "Tweak: " << endl;
  for(const unsigned char &byte : tweak)
    cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);

  cout << endl;

  // Spawn aes-xts kernels and feed them with blocks
  cl_int err;

  // Initialize opencl board
  cl::Context context = initOpenclPlatform();

  cl::Buffer ptxBuffer(context, ptx_h.begin(), ptx_h.end(), true, true, &err);
  checkErr(err, "Buffer::Buffer()");

  cl::Buffer ctxBuffer(context, ctx_h.begin(), ctx_h.end(), false, true, &err);
  checkErr(err, "Buffer::Buffer()");

  cl::Buffer keyBuffer(context, key1.begin(), key1.end(), true, true, &err);
  checkErr(err, "Buffer::Buffer()");

  cl::Buffer tweakBuffer(context, tweak.begin(), tweak.end(), true, true, &err);
  checkErr(err, "Buffer::Buffer()");

  // Get devices from context
  vector<cl::Device> devices;
  devices = context.getInfo<CL_CONTEXT_DEVICES>();
  checkErr(devices.size() > 0 ? CL_SUCCESS : -1, "devices.size() > 0");

  cl::Kernel kernel = createOpenClKernel(context,
      devices,
      "./aes_xts_kernel",
      "aesXtsEncrypt");

  // We are missing the last round to perform ciphertext stealing
  int ptx_size = ptx_h.size() - AES_BLK_BYTES;
  int key_size_bits = key2.size()*8;

  err = kernel.setArg(0, ptxBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(1, keyBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(2, tweakBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(3, ctxBuffer);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(4, key_size_bits);
  checkErr(err, "Kernel::setArg()");
  err = kernel.setArg(5, ptx_size);
  checkErr(err, "Kernel::setArg()");

  // Create command queue and run kernel
  cl::CommandQueue queue(context, devices[0], 0, &err);
  checkErr(err, "CommandQueue::CommandQueue()");cl::Event event;
  err = queue.enqueueNDRangeKernel(kernel,
      cl::NullRange,
      cl::NDRange(4*nblocks),
      cl::NDRange(4),
      NULL,
      &event);
  checkErr(err, "CommandQueue::enqueueNDRangeKernel()");

  // Read results from device
  event.wait();
  err = queue.enqueueReadBuffer(ctxBuffer,
      CL_TRUE,
      0,
      ctx_h.size(),
      ctx_h.data());
  checkErr(err, "CommandQueue::enqueueReadBuffer()");

  // [TODO] Compute last round and perform ctx stealing

}


void xts_test() {

  // Define the key, plaintext, blocks number
  vector<unsigned char> ptx_h;
  vector<unsigned char> key_h;
  vector<unsigned char> iv_h;
  vector<unsigned char> ctx_h;
  vector<unsigned char> ctx_ref;

  ptx_h.resize(ptx_size_xts);
  key_h.resize(xts_key_size * 2);
  iv_h.resize(iv_size);
  ctx_h.resize(ptx_size_xts);
  ctx_ref.resize(ptx_size_xts);

  //// Extract random key, IV and data
  //ifstream urandom("/dev/urandom", ios::in|ios::binary);
  //assert(urandom.good());
  //urandom.read(reinterpret_cast<char*>(ptx_h.data()), ptx_size_xts);
  //urandom.read(reinterpret_cast<char*>(key_h.data()), xts_key_size * 2);
  //urandom.read(reinterpret_cast<char*>(iv_h.data()), iv_size);
  //assert(urandom.good());
  //urandom.close();
  
  iv_h = {0x33, 0x33, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  
  key_h = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
           0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
           0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
           0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};

  ptx_h = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
           0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
           0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
           0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};

  opencl_aes_crypt_xts(ptx_h, key_h, iv_h, ctx_h);

  //cout << endl << "Plaintext: " << endl;
  //for(const unsigned char &byte : ptx_h)
  //  cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  //cout << endl << "Key: " << endl;
  //for(const unsigned char &byte : key_h)
  //  cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  //cout << endl << "Iv: " << endl;
  //for(const unsigned char &byte : iv_h)
  //  cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  //cout << endl << "Ciphertext: " << endl;
  //for(const unsigned char &byte : ctx_h)
  //  cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);

  #ifdef VERIFY
  mbedXtsReference(ptx_h, key_h, iv_h, ctx_ref);

  cout << endl << "Reference Ciphertext: " << endl;
  for(const unsigned char &byte : ctx_ref)
    cout << setfill('0') << setw(2) << hex << static_cast<int>(byte);
  #endif //VERIFY
  
  cout << endl;
}

int main(int argc, char *argv[]) {
  //aes_test();
  xts_test();
}
