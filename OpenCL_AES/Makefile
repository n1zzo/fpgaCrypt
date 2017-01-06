NAME    = aesopencl
CC      = g++
CFLAGS  = -Wall -pedantic -march=native -pipe -O3 -std=c++11 -I $(INCDIR)
LDFLAGS = -lOpenCL -lmbedcrypto
SRCDIR  = ./src
INCDIR  = /usr/include/CL:../mbedtls/include 
LIBDIR  = ../mbedtls/library
BINDIR  = /usr/local/bin
SOURCES = $(SRCDIR)/aes_clean.cpp
KERNELS = $(SRCDIR)/aes_kernel_file.cl
OBJECTS = $(SOURCES:.c=.o)

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(SRCDIR)/%.o: %.c
	$(CC) $^ -c $< $(CFLAGS) $(LDFLAGS)

debug: CFLAGS = -g -Wall -pedantic -O0 -I $(INCDIR) -L $(LIBDIR)
debug: all

clean:
	rm *.o $(NAME)
