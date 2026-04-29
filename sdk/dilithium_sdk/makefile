##############################################
# Dilithium SDK Build Makefile (Updated)
##############################################

CC := gcc
AR := ar
CFLAGS := -O2 -Wall -Wextra \
    -I. \
    -Idilithium \
    -Icommon

LIB := libdilithium.a

COMMON_SRC := $(wildcard common/*.c)
DILITHIUM_SRC := $(wildcard dilithium/*.c)
WRAPPER_SRC := dilithium_api.c

OBJ := $(COMMON_SRC:.c=.o) \
       $(DILITHIUM_SRC:.c=.o) \
       $(WRAPPER_SRC:.c=.o)

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) rcs $(LIB) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(LIB)

##############################################
# Test compile examples (manual usage)
##############################################
# Compile 2-device test:
#   gcc dilithium_2device_test.c -I. -L. -ldilithium -o test_dilithium

# Run:
#   ./test_dilithium
##############################################

