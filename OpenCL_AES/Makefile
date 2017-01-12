NAME       = aesopencl
CC         = g++
CFLAGS     = -Wall -pedantic -march=native -pipe -O3 -std=c++11
LDFLAGS    = -lOpenCL -lmbedcrypto
SRCDIR     = ./src
INCLUDE    = -I /usr/include -I ../mbedtls/include/
LIBDIR     = ../mbedtls/library
BINDIR     = ./bin
SOURCES    = $(SRCDIR)/aes_clean.cpp $(SRCDIR)/cl_errors.cpp
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

emu: host $(AOCX)

host: LDFLAGS += $(shell aocl linkflags)
host: all

$(SRCDIR)/%.aocx: $(SRCDIR)/%.cl
	aoc -march=emulator -v --board $(BOARD) $^ -o $@
	@mv $@ $(BINDIR)

clean:
	rm $(BINDIR)/*
	rm nfa_regexp_debug.log nfa_regexp_dump.log nfa_regexp_run.log
	rm -rf $(SRCDIR)/aes_kernel $(SRCDIR)/aes_kernel.aoco

