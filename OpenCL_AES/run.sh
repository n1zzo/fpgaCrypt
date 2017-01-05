#!/bin/bash

MYPATH= "`pwd`"

DIR= "/home/fumagalli/source/OpenCL/bin/linux/release/"

cd `echo $DIR`
./"aes_host_file_ok"
cd `echo $MYPATH`
