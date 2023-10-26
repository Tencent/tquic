
BUILD_DIR = ../../../target/
LIB_DIR = $(BUILD_DIR)/debug
INCLUDE_DIR = ../../../include

INCS = -I$(INCLUDE_DIR)
CFLAGS = -I. -Wall -Werror -pedantic -fsanitize=address -g -static-libasan -I../../../src/third_party/boringssl/src/include/

LDFLAGS = -L$(LIB_DIR)

LIBS = $(LIB_DIR)/libtquic.a -lev -ldl -lm

all: simple_server

simple_server: simple_server.c $(INCLUDE_DIR)/tquic.h $(LIB_DIR)/libtquic.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

clean:
	@$(RM) -rf simple_server
