NAME    = aesopencl
CC      = g++
CFLAGS  = -Wall -pedantic -march=native -pipe -O3 -I $(INCDIR)
LDFLAGS = -lOpenCL
SRCDIR  = ./src
INCDIR  = ./include
BINDIR  = /usr/local/bin
SOURCES = $(SRCDIR)/aes_host.cpp
KERNELS = $(SRCDIR)/aes_kernel_file.cl
OBJECTS = $(SOURCES:.c=.o)

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(SRCDIR)/%.o: %.c
	$(CC) $^ -c $< $(CFLAGS) $(LDFLAGS)

clean:
	rm *.o $(NAME)
