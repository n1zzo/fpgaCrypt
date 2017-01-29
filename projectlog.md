# Embedded Systems Project Log
### Implementation and analysis of crypto algorithms with the Altera openCL
### to FPGA compiler.

The initial roadmap of the project is:

- find a decent openCL implementation of AES, SHA2 and SHA3
- if there aren't any port the mbedTLS C implementation to openCL
- implement XTS mode of operation for AES
- implement simultaneous hash and Merkle-tree for SHA2 and SHA3
- test the openCL code, using one of the openCL backends (for GPU or CPU)
- deploy Altera openCL SDK and test it with simple openCL kernels
- port the openCL crypto implementation to the Altera toolkit
- test the code on the Altera simulator or on boards if available
- implement some benchmarks to compare FPGA with traditional GPGPUs
- do some design space exploration based on openCL kernel sizes
- eventually port the openCL code on Xilinx SDK

Zoni proposes the following suggestions:

- implement just a single algorithm (AES-XTS) and go through the hardware
- examine the power consumption of the implementation

Use NIST benchmarks for testing AES.


Implement AES-XTS mode of operation in OpenCL.
There is a patch for mbedTLS which passes the test vector and can be used
as reference.

[AES-XTS implementation for mbedtls](https://github.com/ARMmbed/mbedtls/pull/414/files)

The tweak generation is performed sequentially on the host,
however can be parallelized playing with the bit shift size.
If we have N blocks, N-1 kernel will be spawned and fed with
each block, and the second key. Then the final block
will be computed and ciphertext stealing performed.

