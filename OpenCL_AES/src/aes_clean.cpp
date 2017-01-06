#include <utility>
#include <CL/cl.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <iterator>
#include <vector>

using namespace std;

const unsigned int key_length = 256;         // Key size in bits
const unsigned int key_size = key_length/8;  // Key size in bytes
const unsigned int ptx_size = 16;            // Plaintext size in bytes

inline void checkErr(cl_int err, const char * name) {
  if (err != CL_SUCCESS) {
    std::cerr << "ERROR: " << name  << " (" << err << ")" << std::endl;
    exit(EXIT_FAILURE);
  }
}

int main(void) {
  // Opencl Device introspection
  cl_int err;
  vector< cl::Platform > platformList;
  cl::Platform::get(&platformList);
  checkErr(platformList.size()!=0 ? CL_SUCCESS : -1, "cl::Platform::get");
  std::cerr << "Platform number is: " << platformList.size() << std::endl;std::string platformVendor;
  platformList[0].getInfo((cl_platform_info)CL_PLATFORM_VENDOR, &platformVendor);
  std::cerr << "Platform is by: " << platformVendor << "\n";
  cl_context_properties cprops[3] = {CL_CONTEXT_PLATFORM, (cl_context_properties)(platformList[0])(), 0};
  cl::Context context(CL_DEVICE_TYPE_CPU,
                      cprops,
                      NULL,
                      NULL,
                      &err);
  checkErr(err, "Context::Context()");

  // Buffer creation
  unsigned char * ptx_h = new unsigned char[ptx_size];
  unsigned char * ctx_h = new unsigned char[ptx_size];
  unsigned char * key_h = new unsigned char[key_size];

  cl::Buffer ptxBuffer(context,
                       CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                       ptx_size,
                       ptx_h,
                       &err);
                       checkErr(err, "Buffer::Buffer()");
  
  cl::Buffer ctxBuffer(context,
                       CL_MEM_WRITE_ONLY | CL_MEM_USE_HOST_PTR,
                       ptx_size,
                       ctx_h,
                       &err);
                       checkErr(err, "Buffer::Buffer()");

  cl::Buffer keyBuffer(context,
                       CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR,
                       key_size,
                       key_h,
                       &err);
                       checkErr(err, "Buffer::Buffer()");

  // Get devices from context
  vector<cl::Device> devices;
  devices = context.getInfo<CL_CONTEXT_DEVICES>();
  checkErr(devices.size() > 0 ? CL_SUCCESS : -1, "devices.size() > 0");
  
  // Open and build kernel
  std::ifstream file("./src/aes_kernel.cl");
  checkErr(file.is_open() ? CL_SUCCESS:-1, "./src/aes_kernel.cl");
  std::string prog(std::istreambuf_iterator<char>(file),
                   (std::istreambuf_iterator<char>()));
  cl::Program::Sources source(1, std::make_pair(prog.c_str(), prog.length()+1));
  cl::Program program(context, source);
  err = program.build(devices,"");
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
                                   cl::NDRange(1, 1),
                                   NULL,
                                   &event);
  checkErr(err, "ComamndQueue::enqueueNDRangeKernel()");
  
  // Read results from device
  event.wait();
  err = queue.enqueueReadBuffer(ctxBuffer,
                                CL_TRUE,
                                0,
                                ptx_size,
                                ctx_h);
  checkErr(err, "ComamndQueue::enqueueReadBuffer()");

  // Print results
  cout << "Plaintext is:  ";
  for(const char &i : ptx_h) {
    printf("%02X ", i);
  }
  cout << "Key is:        ";
  for(const char &i : key_h) {
    printf("%02X ", i);
  }
  cout << "Ciphertext is: ";
  for(const char &i : ctx_h) {
    printf("%02X ", i);
  }
  cout << endl;
  return EXIT_SUCCESS;
}
