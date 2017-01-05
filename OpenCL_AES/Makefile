NAME    = myprog
CC      = gcc
CFLAGS  = -Wall -pedantic -march=native -pipe -O3 -I $(INCDIR)
LDFLAGS = 
SRCDIR  = ./src
INCDIR  = ./include
BINDIR  = /usr/local/bin
SOURCES = $(SRCDIR)/aes_host.cpp $(SRCDIR)/aes_kernel_file.cl
OBJECTS = $(SOURCES:.c=.o)

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(SRCDIR)/%.o: %.c
	$(CC) $^ -c $< $(CFLAGS) $(LDFLAGS)

clean:
	rm *.o $(NAME)
