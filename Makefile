CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Iinclude
TARGET = mkfs shell

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c, %.o, $(SRCS))

.PHONY: all clean

all: $(TARGET)

mkfs: mkfs.o disk.o bitmap.o
	$(CC) $(CFLAGS) $^ -o $@

shell: shell.o fs_api.o disk.o bitmap.o
	$(CC) $(CFLAGS) $^ -o $@

# $^: all dependencies
# $<: dependency
# $@: target
%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

cleana: clean
	rm -f $(TARGET) simfs.img