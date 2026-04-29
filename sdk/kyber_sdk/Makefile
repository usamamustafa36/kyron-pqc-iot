# Compiler and flags
# Compiler and flags
CC = gcc
AR = ar
LDFLAGS += -lsqlite3
# Base optimization flags (valid everywhere)
BASEFLAGS = -O3 -Wall -Wextra -fPIC -fno-stack-protector -fno-builtin \
            -I. -I./kyber -I./common -I./utils -ffreestanding

# If building on Raspberry Pi → enable ARM optimizations
ifeq ($(shell uname -m),aarch64)
    CFLAGS = $(BASEFLAGS) -mcpu=cortex-a53 -mtune=cortex-a53
else
    CFLAGS = $(BASEFLAGS)   # For Ubuntu x86 (your current PC)
endif



# Object directory
OBJDIR = obj

# Kyber sources (local kyber folder)
KYBER_SRCS = kyber/cbd.c \
             kyber/indcpa.c \
             kyber/kem.c \
             kyber/ntt.c \
             kyber/poly.c \
             kyber/polyvec.c \
             kyber/reduce.c \
             kyber/symmetric-shake.c \
             kyber/verify.c

# Common sources
COMMON_SRCS = common/fips202.c \
              common/aes.c \
              common/sha2.c

# Utils sources
UTILS_SRCS = utils/randombytes.c

# SDK sources
SDK_SRCS = kyber_api.c

# Object files
OBJS = $(patsubst kyber/%.c,$(OBJDIR)/kyber_%.o,$(KYBER_SRCS)) \
       $(patsubst common/%.c,$(OBJDIR)/common_%.o,$(COMMON_SRCS)) \
       $(patsubst utils/%.c,$(OBJDIR)/utils_%.o,$(UTILS_SRCS)) \
       $(OBJDIR)/kyber_api.o

.PHONY: all clean

# Default target
all: libkyber.a

# Build the static library
libkyber.a: $(OBJS)
	$(AR) rcs $@ $^

# Compile Kyber sources
$(OBJDIR)/kyber_%.o: kyber/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile Common sources
$(OBJDIR)/common_%.o: common/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile Utils sources
$(OBJDIR)/utils_%.o: utils/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile SDK source
$(OBJDIR)/kyber_api.o: kyber_api.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Ensure object directory exists
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Clean
clean:
	rm -rf $(OBJDIR) libkyber.a

