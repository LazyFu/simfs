#include <stdint.h>

int open_disk(const char *path, int create);
void close_disk();
int read_block(uint32_t block_id, void *buffer);
int write_block(uint32_t block_id, const void *buffer);