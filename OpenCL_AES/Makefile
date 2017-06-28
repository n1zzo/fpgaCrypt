NAME       = aesopencl
CC     	   = g++
CFLAGS     = -Wall -pedantic -march=native -pipe -O3 -std=c++11
LDFLAGS    = -lOpenCL -lmbedcrypto
SRCDIR     = ./src
INCLUDE    = -I /usr/include -I $(MBEDTLS)/include/ -I ./common/inc
LIBDIR     = $(MBEDTLS)/library
BINDIR     = ./bin
SOURCES    = $(SRCDIR)/aes_clean.cpp $(SRCDIR)/cl_errors.cpp ./common/src/AOCLUtils/*.cpp
KERNELS    = $(SRCDIR)/aes_kernel.cl $(SRCDIR)/aes_xts_kernel.cl
AOCX       = $(KERNELS:.cl=.aocx)
OBJECTS    = $(SOURCES:.c=.o)
BOARD      = attila_v3_prod
MBEDTLS    = ../mbedtls-xts

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $(INCLUDE) $^ -o $@ $(CFLAGS) $(LDFLAGS) -L $(LIBDIR)
	mkdir -p $(BINDIR)
	@mv $@ $(BINDIR)/$@

$(SRCDIR)/%.o: %.cpp
	$(CC) $(INCLUDE) $^ -c $< $(CFLAGS) $(LDFLAGS)

debug: CFLAGS = -g -Wall -pedantic -O0 -std=c++11
debug: host emu

fpga: host $(AOCX)

profile: AOCFLAGS = --profile
profile: host $(AOCX)

emu: AOCFLAGS = -march=emulator --profile
emu: host $(AOCX)

host: LDFLAGS += $(shell aocl linkflags)
host: LDFLAGS += -I /home/opencl-crypt/intelFPGA_pro/17.0/hld/host/include20/
host: $(NAME)

$(SRCDIR)/%.aocx: $(SRCDIR)/%.cl
	time aoc $(AOCFLAGS) -v $^ -o $@ --board $(BOARD)
	@mv $@ $(BINDIR)

run:    host emu
	cd $(BINDIR); env CL_CONTEXT_EMULATOR_DEVICE_ALTERA=1 ./$(NAME)

clean:
	rm -f $(BINDIR)/*
	rm -f nfa_regexp_debug.log nfa_regexp_dump.log nfa_regexp_run.log
	rm -rf $(SRCDIR)/aes_kernel $(SRCDIR)/aes_xts_kernel
	rm -f $(SRCDIR)/aes_kernel.aoco $(SRCDIR)/aes_xts_kernel.aoco

