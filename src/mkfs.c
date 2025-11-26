#include "disk.h"
#include "bitmap.h"
#include "fs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[])
{
    char *disk_path;
    if (argc == 1)
    {
        disk_path = "simfs.img";
    }
    else
    {
        disk_path = argv[1];
    }

    if (open_disk(disk_path, 1) != 0)
    {
        printf("Failed to open or create disk file.\n");
        return 1;
    }

    uint32_t super_block_blocks = 1;

    uint32_t ibmp_bytes = (TOTAL_INODES + 7) / 8;
    // eqauls 1
    uint32_t ibmp_blocks = (ibmp_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;

    uint32_t bbmp_bytes = (TOTAL_BLOCKS + 7) / 8;
    // equals 1
    uint32_t bbmp_blocks = (bbmp_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;

    uint32_t itable_bytes = TOTAL_INODES * INODE_SIZE;
    // equals 400
    uint32_t itable_blocks = (itable_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;

    uint32_t super_block_start = 1;
    uint32_t ibmp_start = super_block_start + super_block_blocks;
    uint32_t bbmp_start = ibmp_start + ibmp_blocks;
    uint32_t itable_start = bbmp_start + bbmp_blocks;
    uint32_t data_start = itable_start + itable_blocks;

    struct SuperBlock *sb = calloc(1, sizeof(struct SuperBlock));
    if (!sb)
    {
        printf("Memory allocation failed for SuperBlock.\n");
        close_disk();
        return 1;
    }
    sb->magic = MAGIC_NUMBER;
    sb->block_size = BLOCK_SIZE;
    sb->block_count = TOTAL_BLOCKS;
    sb->inode_count = TOTAL_INODES;
    sb->inode_bitmap = ibmp_start;  /* 2 */
    sb->block_bitmap = bbmp_start;  /* 3 */
    sb->inode_table = itable_start; /* 4 */
    sb->data_blocks = data_start;   /* 404 */
    sb->free_inodes = TOTAL_INODES;
    sb->free_blocks = TOTAL_BLOCKS - data_start;

    // Initialize inode bitmap to zero
    uint8_t *ibmp = calloc(1, ibmp_blocks * BLOCK_SIZE);
    if (!ibmp)
    {
        printf("Memory allocation failed for inode bitmap.\n");
        free(sb);
        close_disk();
        return 1;
    }
    // Initialize block bitmap to zero
    uint8_t *bbmp = calloc(1, bbmp_blocks * BLOCK_SIZE);
    if (!bbmp)
    {
        printf("Memory allocation failed for block bitmap.\n");
        close_disk();
        free(sb);
        free(ibmp);
        return 1;
    }

    for (uint32_t i = 0; i < data_start; i++)
    {
        set_bitmap_bit(bbmp, i);
    }
    sb->free_blocks -= data_start;

    set_bitmap_bit(ibmp, 0); // Reserve Inode 0
    sb->free_inodes--;

    // Create root directory
    struct Inode *itable = calloc(TOTAL_INODES, sizeof(struct Inode));
    if (!itable)
    {
        printf("Memory allocation failed for Inode Table.\n");
        free(sb);
        free(ibmp);
        free(bbmp);
        close_disk();
        return 1;
    }

    struct Inode *root_inode = &itable[1]; // Inode 1

    root_inode->mode = FS_FT_DIR | 0755; // rwxr-xr-x
    root_inode->link_count = 2;          // this and parent link
    root_inode->uid = 0;                 // root user
    root_inode->size = 2 * sizeof(struct DirEntry);
    root_inode->block_count = 1;
    root_inode->ctime = root_inode->mtime = root_inode->atime = (uint32_t)time(NULL);

    uint32_t root_data_block = data_start; // 403
    root_inode->direct_blocks[0] = root_data_block;

    write_block(itable_start, itable);
    set_bitmap_bit(ibmp, 1);
    sb->free_inodes--;

    uint8_t *root_data_ptr = calloc(1, BLOCK_SIZE);
    if (!root_data_ptr)
    {
        printf("Memory allocation failed for root data block.\n");
        free(sb);
        free(ibmp);
        free(bbmp);
        free(itable);
        close_disk();
        return 1;
    }

    struct DirEntry *entry = (struct DirEntry *)root_data_ptr;

    entry[0].inode = 1;
    strncpy(entry[0].filename, ".", MAX_FILENAME_LENGTH);
    entry[0].filename[MAX_FILENAME_LENGTH - 1] = '\0';

    entry[1].inode = 1;
    strncpy(entry[1].filename, "..", MAX_FILENAME_LENGTH);
    entry[1].filename[MAX_FILENAME_LENGTH - 1] = '\0';

    write_block(root_data_block, root_data_ptr);
    set_bitmap_bit(bbmp, root_data_block);
    sb->free_blocks--;

    write_block(ibmp_start, ibmp);
    write_block(bbmp_start, bbmp);

    if (write_block(super_block_start, sb) != 0)
    {
        printf("Failed to write superblock.\n");
        free(sb);
        close_disk();
        return 1;
    }

    free(sb);
    free(ibmp);
    free(bbmp);
    free(itable);
    free(root_data_ptr);
    close_disk();
    printf("Filesystem created successfully on %s\n", disk_path);
    return 0;
}