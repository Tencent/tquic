TQUIC_DIR = .
LIB_DIR = $(TQUIC_DIR)/target/release
INCLUDE_DIR = $(TQUIC_DIR)/include

INCS = -I$(INCLUDE_DIR)
CFLAGS = -I. -Wall -Werror -pedantic -fsanitize=address -g -static-libasan -I$(TQUIC_DIR)/deps/boringssl/src/include/

LDFLAGS = -L$(LIB_DIR)

LIBS = $(LIB_DIR)/libtquic.a -lev -ldl -lm

all: simple_server simple_client 

simple_server: simple_server.c $(LIB_DIR)/libtquic.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

simple_client: simple_client.c $(LIB_DIR)/libtquic.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)



$(LIB_DIR)/libtquic.a:
	cargo build --release -F ffi

clean:
	@$(RM) -rf simple_server simple_client 
