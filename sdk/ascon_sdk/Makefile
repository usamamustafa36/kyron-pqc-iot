CC = gcc
CFLAGS = -O2 -Wall -Wextra -fPIC \
         -I../utils \
         -I../include \
         -I../include/ascon \
         -I./ascon \
         -I.

OBJDIR = obj

# Source files in ascon/ folder
ASCON_SRCS = ascon/aead.c ascon/printstate.c

# Local SDK sources
SDK_SRCS = ascon_api.c ascon_hash.c
UTIL_SRCS = randombytes.c

# Object files
OBJS = $(patsubst ascon/%.c,$(OBJDIR)/ascon/%.o,$(ASCON_SRCS)) \
       $(patsubst %.c,$(OBJDIR)/%.o,$(SDK_SRCS)) \
       $(patsubst %.c,$(OBJDIR)/%.o,$(UTIL_SRCS))

.PHONY: all clean

all: libascon.a

# Create obj folders
$(OBJDIR):
	mkdir -p $(OBJDIR)
	mkdir -p $(OBJDIR)/ascon

# Compile ascon/*.c files
$(OBJDIR)/ascon/%.o: ascon/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile local SDK .c files
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create static library
libascon.a: $(OBJS)
	ar rcs $@ $^

clean:
	rm -rf $(OBJDIR) libascon.a

