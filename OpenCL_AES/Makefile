NAME    = aesopencl
CC      = g++
CFLAGS  = -Wall -pedantic -march=native -pipe -O3 -I $(INCDIR)
LDFLAGS = -lOpenCL
SRCDIR  = ./src
INCDIR  = /usr/include/CL
BINDIR  = /usr/local/bin
SOURCES = $(SRCDIR)/aes_clean.cpp
KERNELS = $(SRCDIR)/aes_kernel_file.cl
OBJECTS = $(SOURCES:.c=.o)

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(SRCDIR)/%.o: %.c
	$(CC) $^ -c $< $(CFLAGS) $(LDFLAGS)

debug: CFLAGS = -g -Wall -pedantic -O0 -I $(INCDIR)
debug: all

clean:
	rm *.o $(NAME)
