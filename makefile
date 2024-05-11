CC = gcc
CFLAGS = -fPIC
OBJECT = c25519.o
SHARED_LIB = libcurve25519.so
all: $(SHARED_LIB)
$(OBJECT): c25519.c
	$(CC) $(CFLAGS) -c c25519.c -o $(OBJECT)
$(SHARED_LIB): $(OBJECT)
	$(CC) -shared -o $(SHARED_LIB) $(OBJECT)
clean:
	rm -f $(OBJECT) $(SHARED_LIB)
