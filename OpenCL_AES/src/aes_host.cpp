/**
 *
 *    Sistema di criptaggio con algoritmo AES che utilizza la GPU come base di calcolo
 *
 *    \original author Marco Fumagalli
 */
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include <CL/cl.hpp>
#include <assert.h>

using std::cout;
using std::endl;

/**
 *
 *   Controlla se c'e` stato qualche errore nelle chiamate di OpenCL
 *   Individua il tipo di errore e lo stampa a video
 *
 *   \param msg messaggio da stampare a video con il tipo di errore
 *   \param err variabile per il controllo dell'errore
 */
void checkError(const char* msg, cl_int err);

int main(int argc, const char **argv)
{
	const unsigned int size = 32;
	const unsigned int mem_size = sizeof(float)*size;
	
	//OpenCl variables
	cl_platform_id platform;
	cl_device_id device;
	cl_context context;
	cl_command_queue queue;
	cl_int error = CL_SUCCESS;
	cl_uint num_of_platforms=0;
	
	//Device variables
	cl_mem data_array_d;
	cl_mem res_d;
	cl_mem key_d;
	cl_mem size_key_d;
	cl_kernel vector_k;
	float* res_h = new float[size];
	size_t local_ws = 4;
	
	// Initializing the basic OpenCL environment
	error = clGetPlatformIDs(1, &platform, &num_of_platforms);
	checkError("initialization platform", error);

	error = clGetDeviceIDs(platform, CL_DEVICE_TYPE_CPU, 1, &device, NULL);
	checkError("initialization device", error);
	
	context = clCreateContext(NULL, 1, &device, NULL, NULL, &error);
	checkError("initialization context", error);
	
	queue = clCreateCommandQueue(context, device, 0, &error);
	checkError("initialization queue", error);
	
	//Initializing host memory
	float* data_array_h = new float[size];
	
	for (unsigned int i = 0; i < size; i++) 
	{
		data_array_h[i] =  2.0f*i;
	}
	
	//Creates the program
	std::ifstream kernel("./src/aes_kernel_file.cl");
	std::string content((std::istreambuf_iterator<char>(kernel)),
                        std::istreambuf_iterator<char>());
	const char *source = content.c_str();
	size_t source_size = content.size();

	cl_program program = clCreateProgramWithSource(context, 1, &source, &source_size, &error);
	checkError("Creating program", error);
	
		//Initializing device memory
		data_array_d = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, mem_size, res_h, &error);
		checkError("initialization device memory data", error);
		
		res_d = clCreateBuffer(context, CL_MEM_WRITE_ONLY, mem_size, NULL, &error);
		checkError("initialization device memory result", error);
		
		key_d = clCreateBuffer(context, CL_MEM_READ_ONLY, mem_size, NULL, &error);
		checkError("initialization device memory key", error);
	
	    size_key_d = clCreateBuffer(context, CL_MEM_READ_ONLY, mem_size, NULL, &error);
	    checkError("initialization device memory key size", error);
			
		//Builds the program
		error = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
		checkError("Building program", error);
	
	char build[2048];
	clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 2048, build, NULL);
	printf("Build Log:  %s\n",build);
		
		// 'Extracting' the kernel
		vector_k = clCreateKernel(program, "aesEncrypt", &error);
		checkError("'Extracting' the kernel", error);
		
		error = clSetKernelArg(vector_k, 0, sizeof(cl_mem), &data_array_d);
		error |= clSetKernelArg(vector_k, 1, sizeof(cl_mem), &key_d);
		error |= clSetKernelArg(vector_k, 2, sizeof(cl_mem), &res_d);
	    error |= clSetKernelArg(vector_k, 3, sizeof(cl_mem), &size_key_d);
		error |= clSetKernelArg(vector_k, 4, sizeof(size_t), &size);
		checkError("queue", error);
			
		// Launching kernel
	const size_t global_ws = 1024;
	local_ws = 64;
		error = clGetKernelWorkGroupInfo(vector_k, device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(local_ws), &local_ws, NULL);
		checkError("Launching get kernel work group", error);
		error = clEnqueueNDRangeKernel(queue, vector_k, 1, NULL, &global_ws, &local_ws, 0, NULL, NULL);
		checkError("Launching kernel", error);
			
		// Reading back
		clEnqueueReadBuffer(queue, res_d, CL_TRUE, 0, mem_size, res_h, 0, NULL, NULL);

	
	
	// Checking with the CPU results;
	//checkError("result", error);
	
	
	// Cleaning up
	delete[] data_array_h;
	//delete[] check;
	clReleaseKernel(vector_k);
	clReleaseCommandQueue(queue);
	clReleaseContext(context);
	clReleaseMemObject(data_array_d);
	clReleaseMemObject(res_d);
	
	printf("It Run Correctly!\n");
	return 0;
	
}


void checkError(const char* msg, cl_int err)
{
	if(err != CL_SUCCESS)
	{
		const char * error_cl;
		switch (err) 
		{
			case CL_DEVICE_NOT_FOUND:
				error_cl = "CL_DEVICE_NOT_FOUND";
				break;
			case CL_DEVICE_NOT_AVAILABLE:
				error_cl = "CL_DEVICE_NOT_AVAILABLE";
				break;
			case CL_COMPILER_NOT_AVAILABLE:
				error_cl = "CL_COMPILER_NOT_AVAILABLE";
				break;
			case CL_MEM_OBJECT_ALLOCATION_FAILURE:
				error_cl = "CL_MEM_OBJECT_ALLOCATION_FAILURE";
				break;
			case CL_OUT_OF_RESOURCES:
				error_cl = "CL_OUT_OF_RESOURCES";
				break;
			case CL_OUT_OF_HOST_MEMORY:
				error_cl = "CL_OUT_OF_HOST_MEMORY";
				break;
			case CL_PROFILING_INFO_NOT_AVAILABLE:
				error_cl = " CL_PROFILING_INFO_NOT_AVAILABLE";
				break;
			case CL_MEM_COPY_OVERLAP:
				error_cl = "CL_MEM_COPY_OVERLAP";
				break;
			case CL_IMAGE_FORMAT_MISMATCH:
				error_cl = "CL_IMAGE_FORMAT_MISMATCH";
				break;
			case CL_IMAGE_FORMAT_NOT_SUPPORTED:
				error_cl = "CL_IMAGE_FORMAT_NOT_SUPPORTED";
				break;
			case CL_BUILD_PROGRAM_FAILURE:
				error_cl = "CL_BUILD_PROGRAM_FAILURE";
				break;
			case CL_MAP_FAILURE:
				error_cl = " CL_MAP_FAILURE";
				break;
			case CL_INVALID_VALUE:
				error_cl = "CL_INVALID_VALUE";
				break;
			case CL_INVALID_DEVICE_TYPE:
				error_cl = "CL_INVALID_DEVICE_TYPE";
				break;
			case CL_INVALID_PLATFORM:
				error_cl = "CL_INVALID_PLATFORM";
				break;
			case CL_INVALID_DEVICE:
				error_cl = "CL_INVALID_DEVICE";
				break;
			case CL_INVALID_CONTEXT:
				error_cl = "CL_INVALID_CONTEXT";
				break;
			case CL_INVALID_QUEUE_PROPERTIES:
				error_cl = "CL_INVALID_QUEUE_PROPERTIES";
				break;
			case CL_INVALID_COMMAND_QUEUE:
				error_cl = "CL_INVALID_COMMAND_QUEUE";
				break;
			case CL_INVALID_HOST_PTR:
				error_cl = "CL_INVALID_HOST_PTR";
				break;
			case CL_INVALID_MEM_OBJECT:
				error_cl = "CL_INVALID_MEM_OBJECT";
				break;
			case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:
				error_cl = "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
				break;
			case CL_INVALID_IMAGE_SIZE:
				error_cl = "CL_INVALID_IMAGE_SIZE";
				break;
			case CL_INVALID_SAMPLER:
				error_cl = "CL_INVALID_SAMPLER";
				break;
			case CL_INVALID_BINARY:
				error_cl = "CL_INVALID_BINARY";
				break;
			case CL_INVALID_BUILD_OPTIONS:
				error_cl = "CL_INVALID_BUILD_OPTIONS";
				break;
			case CL_INVALID_PROGRAM:
				error_cl = "CL_INVALID_PROGRAM";
				break;
			case CL_INVALID_PROGRAM_EXECUTABLE:
				error_cl = "CL_INVALID_PROGRAM_EXECUTABLE";
				break;
			case CL_INVALID_KERNEL_NAME:
				error_cl = "CL_INVALID_KERNEL_NAME";
				break;
			case CL_INVALID_KERNEL_DEFINITION:
				error_cl = "CL_INVALID_KERNEL_DEFINITION";
				break;
			case CL_INVALID_KERNEL:
				error_cl = "CL_INVALID_KERNEL";
				break;
			case CL_INVALID_ARG_INDEX:
				error_cl = "CL_INVALID_ARG_INDEX";
				break;
			case CL_INVALID_ARG_VALUE:
				error_cl = "CL_INVALID_ARG_VALUE";
				break;
			case CL_INVALID_ARG_SIZE:
				error_cl = "CL_INVALID_ARG_SIZE";
				break;
			case CL_INVALID_KERNEL_ARGS:
				error_cl = "CL_INVALID_KERNEL_ARGS";
				break;
			case CL_INVALID_WORK_DIMENSION:
				error_cl = "CL_INVALID_WORK_DIMENSION";
				break;
			case CL_INVALID_WORK_GROUP_SIZE:
				error_cl = "CL_INVALID_WORK_GROUP_SIZE";
				break;
			case CL_INVALID_WORK_ITEM_SIZE:
				error_cl = "CL_INVALID_WORK_ITEM_SIZE";
				break;
			case CL_INVALID_EVENT_WAIT_LIST:
				error_cl = "CL_INVALID_EVENT_WAIT_LIST";
				break;
			case CL_INVALID_EVENT:
				error_cl = "CL_INVALID_EVENT";
				break;
			case CL_INVALID_OPERATION:
				error_cl = "CL_INVALID_OPERATION";
				break;
			case CL_INVALID_GL_OBJECT:
				error_cl = "CL_INVALID_GL_OBJECT";
				break;
			case CL_INVALID_BUFFER_SIZE:
				error_cl = "CL_INVALID_BUFFER_SIZE";
				break;
			case CL_INVALID_MIP_LEVEL:
				error_cl = "CL_INVALID_MIP_LEVEL";
				break;
			case CL_INVALID_GLOBAL_WORK_SIZE:
				error_cl = "CL_INVALID_GLOBAL_WORK_SIZE";
				break;
				
			default:
				error_cl = "BOH";
				break;
		}
		
		printf("ERROR: %s %s\n", msg, error_cl);
		//exit(-1);
	}
}


