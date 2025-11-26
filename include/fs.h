#ifndef FS_H
#define FS_H
#include <stdint.h>

/* see https://en.wikipedia.org/wiki/Hexspeak */
#define MAGIC_NUMBER 0x1A27F00
#define BLOCK_SIZE 4096
#define INODE_SIZE 128
#define TOTAL_BLOCKS 12800 // 50 MB disk with 4KB block size
#define TOTAL_INODES 12800
#define MAX_FILENAME_LENGTH 28

/* fs partition layout
 * +-----------------+
 * |   boot block    |    empty
 * +-----------------+
 * |   superblock    |
 * +-----------------+
 * |   inode bitmap  |
 * +-----------------+
 * |   block bitmap  |
 * +-----------------+
 * |   inode table   |
 * +-----------------+
 * |   data blocks   |
 * +-----------------+
 */

// 4096 bytes for superblock
struct SuperBlock
{
    uint32_t magic;
    uint32_t block_size;               /* each block size in bytes */
    uint32_t block_count;              /* total number of blocks */
    uint32_t inode_count;              /* total number of inodes */
    uint32_t inode_bitmap;             /* where inode bitmap start */
    uint32_t block_bitmap;             /* where block bitmap start */
    uint32_t inode_table;              /* where inode table start */
    uint32_t data_blocks;              /* where data blocks start */
    uint32_t free_inodes;              /* number of free inodes */
    uint32_t free_blocks;              /* number of free blocks */
    uint8_t reserved[BLOCK_SIZE - 40]; /* padding to fill the block */
};

#define DIRECT_PTRS 12    // 12*4=48 bytes maximum
#define FS_FT_DIR 0x4000  // Directory
#define FS_FT_FILE 0x8000 // Regular file

/* the time uint32_t can not exceed 2038.1.19
 * see https://en.wikipedia.org/wiki/Year_2038_problem
 */
// 128 bytes per inode
struct Inode
{
    uint16_t mode;                       /* file mode and permissions */
    uint16_t link_count;                 /* number of hard links */
    uint32_t uid;                        /* owner user id */
    uint32_t gid;                        /* owner group id */
    uint32_t size;                       /* file size in bytes */
    uint32_t block_count;                /* number of data blocks allocated */
    uint32_t ctime;                      /* creation time */
    uint32_t mtime;                      /* last modification time */
    uint32_t atime;                      /* last access time */
    uint32_t direct_blocks[DIRECT_PTRS]; /* direct data block pointers */
    uint32_t indirect_block;             /* single indirect block pointer */
    uint32_t double_indirect_block;      /* double indirect block pointer */
    uint8_t reserved[INODE_SIZE - 88];   /* padding to fill the inode */
};

// 32 bytes per directory entry
struct DirEntry
{
    uint32_t inode;                     /* inode number */
    char filename[MAX_FILENAME_LENGTH]; /* filename */
};

#endif