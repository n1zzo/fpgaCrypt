NAME       = aesopencl
CC         = g++
CFLAGS     = -Wall -pedantic -march=native -pipe -O3 -std=c++11 -I $(INCDIR)
LDFLAGS    = -lOpenCL -lmbedcrypto
EMULDFLAGS = -L/mnt/residential_zone/home/gpg_keyserver/intelFPGA/16.1/hld/board/s5_ref/linux64/lib -L/mnt/residential_zone/home/gpg_keyserver/intelFPGA/16.1/hld/host/linux64/lib -Wl,--no-as-needed -lalteracl -laltera_s5_ref_mmd -lelf
SRCDIR     = ./src
INCDIR     = /usr/include/CL:../mbedtls/include 
LIBDIR     = ../mbedtls/library
BINDIR     = /usr/local/bin
SOURCES    = $(SRCDIR)/aes_clean.cpp
KERNELS    = $(SRCDIR)/aes_kernel_file.cl
OBJECTS    = $(SOURCES:.c=.o)

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(EMULDFLAGS)
	@mv $@ bin

$(SRCDIR)/%.o: %.c
	$(CC) $^ -c $< $(CFLAGS) $(LDFLAGS)

debug: CFLAGS = -g -Wall -pedantic -O0 -I $(INCDIR) -L $(LIBDIR)
debug: all

clean:
	rm *.o $(NAME)
