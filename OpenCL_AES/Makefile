NAME       = aesopencl
CC	 = g++
CFLAGS     = -Wall -pedantic -march=native -pipe -O3 -std=c++11
LDFLAGS    = -lOpenCL -lmbedcrypto
SRCDIR     = ./src
INCLUDE    = -I /usr/include -I ../mbedtls/include/ -I ./common/inc
LIBDIR     = ../mbedtls/library
BINDIR     = ./bin
SOURCES    = $(SRCDIR)/aes_clean.cpp $(SRCDIR)/cl_errors.cpp ./common/src/AOCLUtils/*.cpp
KERNELS    = $(SRCDIR)/aes_kernel.cl
AOCX       = $(KERNELS:.cl=.aocx)
OBJECTS    = $(SOURCES:.c=.o)
BOARD      = s5_ref

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $(INCLUDE) $^ -o $@ $(CFLAGS) $(LDFLAGS)
	@mv $@ $(BINDIR)

$(SRCDIR)/%.o: %.cpp
	$(CC) $(INCLUDE) $^ -c $< $(CFLAGS) $(LDFLAGS)

debug: CFLAGS = -g -Wall -pedantic -O0 -I $(INCDIR) -L $(LIBDIR)
debug: all

fpga: host $(AOCX)

profile: AOCFLAGS = --profile
profile: host $(AOCX)

emu: AOCFLAGS = -march=emulator
emu: host $(AOCX)

host: LDFLAGS += $(shell aocl linkflags)
host: LDFLAGS += -I /mnt/residential_zone/home/gpg_keyserver/intelFPGA_pro/16.1/hld/host/include20/
host: $(NAME)

$(SRCDIR)/%.aocx: $(SRCDIR)/%.cl
	aoc $(AOCFLAGS) -v --board $(BOARD) $^ -o $@
	@mv $@ $(BINDIR)

run: 
	cd $(BINDIR); env CL_CONTEXT_EMULATOR_DEVICE_ALTERA=1 ./$(NAME)

clean:
	rm $(BINDIR)/*
	rm nfa_regexp_debug.log nfa_regexp_dump.log nfa_regexp_run.log
	rm -rf $(SRCDIR)/aes_kernel $(SRCDIR)/aes_kernel.aoco

