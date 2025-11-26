CC = gcc
CFLAGS = -Wall -std=c99 -Iinclude
TARGET = mkfs

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c, %.o, $(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

# $<: dependency
# $@: target
%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)