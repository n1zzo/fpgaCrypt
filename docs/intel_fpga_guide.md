

# Set environment variables

# Steps to install a new board
- aocl install <- this compiles and installs the correct module for your selected board
- flash a supported OpenCL design on the FPGA
	- download one of the [design examples](https://www.altera.com/products/design-software/embedded-software-developers/opencl/developer-zone.html)
	- compile it for the target board
	- flash it on the board
- aocl diagnose <- to test that everything is working

# Altera SDK tool setup

- Install the combined sw+update `Quartus-pro-16.1.0.196-linux-complete.tar`
- Install `Intel FPGA SDK for OpenCL v16.1 Update 2`
