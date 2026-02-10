CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

BIN_DIR := bin
SRC_DIR := src

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
LDLIBS :=
else
LDLIBS := -lcrypto -lm
endif

.PHONY: all clean test

all: $(BIN_DIR)/pass2hash $(BIN_DIR)/pwgen $(BIN_DIR)/brute

$(BIN_DIR):
	@mkdir -p $@

$(BIN_DIR)/pass2hash: $(SRC_DIR)/pass2hash.c $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(SRC_DIR)/pass2hash.c $(SRC_DIR)/crypto.c -o $@ $(LDLIBS)

$(BIN_DIR)/brute: $(SRC_DIR)/brute.c $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(SRC_DIR)/brute.c $(SRC_DIR)/crypto.c -o $@ $(LDLIBS)

$(BIN_DIR)/pwgen: $(SRC_DIR)/pwgen.c $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(SRC_DIR)/pwgen.c $(SRC_DIR)/crypto.c -o $@ $(LDLIBS)

test: all
	./tests/smoke.sh

clean:
	rm -rf $(BIN_DIR) *.o $(SRC_DIR)/*.o
