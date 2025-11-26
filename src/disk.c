#include "fs.h"
#include <stdio.h>
#include <stdlib.h>

static FILE *g_disk_file = NULL;

// Open the disk file. 0 for not create.
int open_disk(const char *path, int create)
{
    g_disk_file = fopen(path, "r+b");
    if (g_disk_file == NULL)
    {
        if (!create)
        {
            return -1;
        }
        g_disk_file = fopen(path, "w+b");
        if (g_disk_file == NULL)
        {
            return -1;
        }
        long total_size = BLOCK_SIZE * TOTAL_BLOCKS;
        fseek(g_disk_file, total_size - 1, SEEK_SET);
        fputc('\0', g_disk_file);
        fseek(g_disk_file, 0, SEEK_SET);
    }
    return 0;
}

// Close the disk file.
void close_disk()
{
    if (g_disk_file)
    {
        fclose(g_disk_file);
        g_disk_file = NULL;
    }
}

// Read a block from disk into buffer.
int read_block(uint32_t block_id, void *buffer)
{
    if (g_disk_file == NULL || block_id >= TOTAL_BLOCKS)
    {
        return -1;
    }
    long offset = block_id * BLOCK_SIZE;
    fseek(g_disk_file, offset, SEEK_SET);
    size_t read_bytes = fread(buffer, 1, BLOCK_SIZE, g_disk_file);
    return (read_bytes == BLOCK_SIZE) ? 0 : -1;
}

// Write a block from buffer to disk.
int write_block(uint32_t block_id, const void *buffer)
{
    if (g_disk_file == NULL || block_id >= TOTAL_BLOCKS)
    {
        return -1;
    }
    long offset = block_id * BLOCK_SIZE;
    fseek(g_disk_file, offset, SEEK_SET);
    size_t written_bytes = fwrite(buffer, 1, BLOCK_SIZE, g_disk_file);
    fflush(g_disk_file);
    return (written_bytes == BLOCK_SIZE) ? 0 : -1;
}