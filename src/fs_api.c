#define _POSIX_C_SOURCE 200112L // for strtok_r

#include "fs.h"
#include "disk.h"
#include "bitmap.h"
#include "fs_api.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>

#define PTRS_PER_BLOCK (BLOCK_SIZE / 4)
#define DIR_ENTRIES_PER_BLOCK (BLOCK_SIZE / sizeof(struct DirEntry))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX_PATH_LEN 256

static struct SuperBlock *g_superblock = NULL;
static uint8_t *g_inode_bitmap = NULL;
static uint8_t *g_block_bitmap = NULL;
static struct Inode *g_inode_table = NULL;

static struct FileHandle *g_open_file_table = NULL;
static bool *g_fd_in_use = NULL;
static struct FileConcurrency *g_file_concurrency = NULL;

static uint32_t g_cwd_inode = 1; // root inode

static void do_find_recursive(uint32_t dir_inode_id, const char *name);
static int find_free_fd();
static int add_dir_entry(uint32_t parent_inode_id, const char *name, uint32_t inode_id);
static int create_inode_entry(uint32_t parent_inode_id, const char *name, uint16_t mode, uint32_t *new_inode_id);
static int remove_dir_entry(uint32_t parent_inode_id, const char *name);
static int path_walk(const char *path, uint32_t *inode, char *filename);
static uint32_t find_inode_by_name(uint32_t inode, const char *name);
static int find_name_by_inode(uint32_t current_inode_id, uint32_t target_inode_id, char *name_buf);
static uint32_t inode_get_or_create_block(struct Inode *inode, uint32_t logical_idx, bool allocate);
static int check_duplicate(const uint32_t parent_inode_id, const char *name);
static int build_path_from_inode(uint32_t target_inode, char *path_buf, size_t buf_size);
static bool is_dir_empty(const uint32_t dir_inode_id);

int fs_mount(const char *disk_path)
{
    if (open_disk(disk_path, 0) != 0)
    {
        return -1;
    }
    g_superblock = calloc(1, sizeof(struct SuperBlock));
    if (read_block(1, g_superblock) != 0)
    {
        free(g_superblock);
        close_disk();
        return -1;
    }
    if (g_superblock->magic != MAGIC_NUMBER)
    {
        free(g_superblock);
        close_disk();
        return -1;
    }
    g_inode_bitmap = calloc(1, IBMP_BLOCKS * BLOCK_SIZE);
    if (!g_inode_bitmap)
    {
        free(g_superblock);
        close_disk();
        return -1;
    }
    for (uint32_t i = 0; i < IBMP_BLOCKS; i++)
    {
        if (read_block(g_superblock->inode_bitmap + i, g_inode_bitmap + i * BLOCK_SIZE) != 0)
        {
            free(g_superblock);
            free(g_inode_bitmap);
            close_disk();
            return -1;
        }
    }
    g_block_bitmap = calloc(1, BBMP_BLOCKS * BLOCK_SIZE);
    if (!g_block_bitmap)
    {
        free(g_superblock);
        free(g_inode_bitmap);
        close_disk();
        return -1;
    }
    for (uint32_t i = 0; i < BBMP_BLOCKS; i++)
    {
        if (read_block(g_superblock->block_bitmap + i, g_block_bitmap + i * BLOCK_SIZE) != 0)
        {
            free(g_superblock);
            free(g_inode_bitmap);
            free(g_block_bitmap);
            close_disk();
            return -1;
        }
    }
    g_inode_table = calloc(g_superblock->inode_count, sizeof(struct Inode));
    if (!g_inode_table)
    {
        free(g_superblock);
        free(g_inode_bitmap);
        free(g_block_bitmap);
        close_disk();
        return -1;
    }
    for (uint32_t i = 0; i < ITABLE_BLOCKS; i++)
    {
        if (read_block(g_superblock->inode_table + i, (uint8_t *)g_inode_table + i * BLOCK_SIZE) != 0)
        {
            free(g_superblock);
            free(g_inode_bitmap);
            free(g_block_bitmap);
            free(g_inode_table);
            close_disk();
            return -1;
        }
    }
    g_open_file_table = calloc(MAX_OPEN_FILES, sizeof(struct FileHandle));
    g_fd_in_use = calloc(MAX_OPEN_FILES, sizeof(bool));
    g_file_concurrency = calloc(TOTAL_INODES, sizeof(struct FileConcurrency));
    if (!g_open_file_table || !g_fd_in_use || !g_file_concurrency)
    {
        free(g_superblock);
        free(g_inode_bitmap);
        free(g_block_bitmap);
        free(g_inode_table);
        free(g_open_file_table);
        free(g_fd_in_use);
        close_disk();
        return -1;
    }
    g_fd_in_use[0] = true; // stdin fd 0
    g_fd_in_use[1] = true; // stdout fd 1
    g_fd_in_use[2] = true; // stderr fd 2
    return 0;
}

int fs_umount()
{
    bool flag = false;
    for (int i = 3; i < MAX_OPEN_FILES; i++)
    {
        if (g_fd_in_use[i])
        {
            flag = true;
            fs_close(i);
            g_fd_in_use[i] = false;
        }
    }
    if (flag)
    {
        printf("Warning: There were open files during unmount. All opened files have been closed.\n");
    }
    for (uint32_t i = 0; i < ITABLE_BLOCKS; i++)
    {
        if (write_block(g_superblock->inode_table + i, (uint8_t *)g_inode_table + i * BLOCK_SIZE) != 0)
        {
            return -1;
        }
    }
    for (uint32_t i = 0; i < BBMP_BLOCKS; i++)
    {
        if (write_block(g_superblock->block_bitmap + i, g_block_bitmap + i * BLOCK_SIZE) != 0)
        {
            return -1;
        }
    }
    for (uint32_t i = 0; i < IBMP_BLOCKS; i++)
    {
        if (write_block(g_superblock->inode_bitmap + i, g_inode_bitmap + i * BLOCK_SIZE) != 0)
        {
            return -1;
        }
    }
    if (write_block(SUPER_BLOCK_BLOCKS, g_superblock) != 0)
    {
        return -1;
    }
    free(g_superblock);
    free(g_inode_bitmap);
    free(g_block_bitmap);
    free(g_inode_table);
    free(g_open_file_table);
    free(g_fd_in_use);
    free(g_file_concurrency);
    close_disk();
    return 0;
}

int fs_open(const char *path, uint16_t mode)
{
    int fd = find_free_fd();
    if (fd == -1)
    {
        printf("Max open file limit reached.\n");
        return -1;
    }
    uint32_t parent_inode;
    char filename[MAX_FILENAME_LENGTH];
    if (path_walk(path, &parent_inode, filename) != 0)
    {
        return -1;
    }
    uint32_t inode_id = find_inode_by_name(parent_inode, filename);
    if (inode_id == UINT32_MAX)
    {
        printf("No such file: %s\n", path);
        return -1;
    }
    struct Inode *inode = &g_inode_table[inode_id];
    struct FileConcurrency *fc = &g_file_concurrency[inode_id];
    if ((inode->mode & FS_FT_DIR) != 0)
    {
        printf("Is a directory: %s\n", path);
        return -1;
    }
    if (mode & (FS_O_WRITE | FS_O_RW | FS_O_APPEND))
    {
        if (fc->writers > 0 || fc->readers > 0)
        {
            printf("File is busy: %s\n", path);
            return -1;
        }
    }
    else
    {
        if (fc->writers > 0)
        {
            printf("File is busy: %s\n", path);
            return -1;
        }
    }
    if (mode & FS_O_READ)
    {
        fc->readers += 1;
    }
    else
    {
        fc->writers += 1;
    }

    struct FileHandle *fh = &g_open_file_table[fd];
    fh->inode_id = inode_id;
    fh->mode = mode;
    fh->offset = (mode & FS_O_APPEND) ? inode->size : 0;
    fh->is_dirty = false;
    inode->atime = (uint32_t)time(NULL);
    g_fd_in_use[fd] = true;
    return 0;
}

int fs_write(int fd, const void *buf, uint32_t count)
{
    if (fd < 3 || fd >= MAX_OPEN_FILES || !g_fd_in_use[fd])
    {
        printf("Invalid file descriptor: %d\n", fd);
        return -1;
    }
    if (buf == NULL && count > 0)
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }
    struct FileHandle *fh = &g_open_file_table[fd];
    if ((fh->mode & (FS_O_WRITE | FS_O_RW | FS_O_APPEND)) == 0)
    {
        printf("File not opened in write mode: %d\n", fd);
        return -1;
    }

    struct Inode *inode = &g_inode_table[fh->inode_id];
    const uint8_t *src_buf = (const uint8_t *)buf;
    uint32_t bytes_written = 0;
    uint8_t block_buf[BLOCK_SIZE];
    while (bytes_written < count)
    {
        uint32_t logical_block_idx = fh->offset / BLOCK_SIZE;
        uint32_t block_offset = fh->offset % BLOCK_SIZE;

        uint32_t bytes_left_to_write = count - bytes_written;
        uint32_t space_in_block = BLOCK_SIZE - block_offset;
        uint32_t chunk_size = MIN(bytes_left_to_write, space_in_block);

        uint32_t physical_block_id = inode_get_or_create_block(inode, logical_block_idx, true);
        if (physical_block_id == 0)
        {
            return (bytes_written > 0) ? (int)bytes_written : -1;
        }
        // Read-Modify-Write
        bool overwrite_whole_block = (block_offset == 0 && chunk_size == BLOCK_SIZE);
        if (!overwrite_whole_block)
        {
            if (read_block(physical_block_id, block_buf) != 0)
            {
                return -1;
            }
        }
        memcpy(block_buf + block_offset, src_buf + bytes_written, chunk_size);
        if (write_block(physical_block_id, block_buf) != 0)
        {
            return -1;
        }
        fh->offset += chunk_size;
        bytes_written += chunk_size;
        if (fh->offset > inode->size)
        {
            inode->size = fh->offset;
        }
    }
    fh->is_dirty = true;
    printf("Wrote %u bytes to fd %d\n", bytes_written, fd);
    return 0;
}

int fs_read(int fd, void *buf, uint32_t count)
{
    if (fd < 3 || fd >= MAX_OPEN_FILES || !g_fd_in_use[fd])
    {
        printf("Invalid file descriptor: %d\n", fd);
        return -1;
    }
    if (buf == NULL && count > 0)
    {
        return -1;
    }
    struct FileHandle *fh = &g_open_file_table[fd];
    if ((fh->mode & (FS_O_READ | FS_O_RW)) == 0)
    {
        printf("File not opened in read mode: %d\n", fd);
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }

    struct Inode *inode = &g_inode_table[fh->inode_id];
    uint8_t *dest_buf = (uint8_t *)buf;
    uint32_t bytes_read = 0;
    uint8_t block_buf[BLOCK_SIZE];
    while (bytes_read < count)
    {
        if (fh->offset >= inode->size)
        {
            break;
        }
        uint32_t logical_block_idx = fh->offset / BLOCK_SIZE;
        uint32_t block_offset = fh->offset % BLOCK_SIZE;

        uint32_t bytes_remaining_in_file = inode->size - fh->offset;
        uint32_t bytes_left_to_read = count - bytes_read;
        uint32_t space_in_block = BLOCK_SIZE - block_offset;

        uint32_t chunk_size = MIN(bytes_left_to_read, space_in_block);
        chunk_size = MIN(chunk_size, bytes_remaining_in_file);

        uint32_t physical_block_id = inode_get_or_create_block(inode, logical_block_idx, false);
        if (physical_block_id == 0)
        {
            // sparse file, fill with zeros
            if (fh->offset < inode->size)
            {
                memset(dest_buf + bytes_read, 0, chunk_size);
            }
        }
        else
        {
            if (read_block(physical_block_id, block_buf) != 0)
            {
                return bytes_read > 0 ? (int)bytes_read : -1;
            }
            memcpy(dest_buf + bytes_read, block_buf + block_offset, chunk_size);
        }

        fh->offset += chunk_size;
        bytes_read += chunk_size;
    }
    if (bytes_read > 0)
    {
        inode->atime = (uint32_t)time(NULL);
    }
    printf("Read %u bytes from fd %d\n", bytes_read, fd);
    return (int)bytes_read;
}

int fs_close(int fd)
{
    if (fd < 3 || fd >= MAX_OPEN_FILES || !g_fd_in_use[fd])
    {
        printf("Invalid file descriptor: %d\n", fd);
        return -1;
    }
    struct FileHandle *handle = &g_open_file_table[fd];
    struct Inode *target_inode = &g_inode_table[handle->inode_id];
    struct FileConcurrency *fc = &g_file_concurrency[handle->inode_id];
    if (handle->mode & FS_O_READ)
    {
        fc->readers -= 1;
    }
    else
    {
        fc->writers -= 1;
    }

    if (handle->is_dirty)
    {
        target_inode->mtime = (uint32_t)time(NULL);
    }
    g_fd_in_use[fd] = false;

    return 0;
}

int fs_seek(int fd, uint32_t offset)
{
    if (fd < 3 || fd >= MAX_OPEN_FILES || !g_fd_in_use[fd])
    {
        printf("Invalid file descriptor: %d\n", fd);
        return -1;
    }
    struct FileHandle *handle = &g_open_file_table[fd];
    struct Inode *inode = &g_inode_table[handle->inode_id];

    if (offset > inode->size)
    {
        printf("Warning: seeking beyond file size (%u > %u)\n", offset, inode->size);
    }

    handle->offset = offset;
    return 0;
}

int fs_find(const char *name)
{
    if (name == NULL || name[0] == '\0')
    {
        return -1;
    }
    do_find_recursive(g_cwd_inode, name);
    return 0;
}

int fs_create(const char *path, uint16_t mode)
{
    char *filename = calloc(1, MAX_FILENAME_LENGTH);
    uint32_t parent_inode;
    if (path_walk(path, &parent_inode, filename) != 0)
    {
        free(filename);
        return -1;
    }
    if (check_duplicate(parent_inode, filename) != 0)
    {
        free(filename);
        return -1;
    }
    uint32_t new_inode;
    if (create_inode_entry(parent_inode, filename, mode | FS_FT_FILE, &new_inode) != 0)
    {
        free(filename);
        return -1;
    }
    free(filename);
    return 0;
}

int fs_mkdir(const char *path, uint16_t mode)
{
    char *filename = calloc(1, MAX_FILENAME_LENGTH);
    uint32_t parent_inode;
    if (path_walk(path, &parent_inode, filename) != 0)
    {
        free(filename);
        return -1;
    }
    if (check_duplicate(parent_inode, filename) != 0)
    {
        free(filename);
        return -1;
    }
    uint32_t new_inode;
    if (create_inode_entry(parent_inode, filename, mode | FS_FT_DIR, &new_inode) != 0)
    {
        free(filename);
        return -1;
    }
    free(filename);
    return 0;
}

int fs_rmdir(const char *path)
{
    uint32_t parent_inode;
    char filename[MAX_FILENAME_LENGTH];
    if (path_walk(path, &parent_inode, filename) != 0)
    {
        return -1;
    }
    uint32_t inode_id = find_inode_by_name(parent_inode, filename);
    if (inode_id == UINT32_MAX)
    {
        printf("No such directory: %s\n", path);
        return -1;
    }
    struct Inode *inode = &g_inode_table[inode_id];
    if ((inode->mode & FS_FT_DIR) == 0)
    {
        printf("Not a directory: %s\n", path);
        return -1;
    }
    if (is_dir_empty(inode_id) == false)
    {
        printf("Directory not empty: %s\n", path);
        return -1;
    }
    if (remove_dir_entry(parent_inode, filename) != 0)
    {
        return -1;
    }
    g_inode_table[parent_inode].link_count -= 1;
    return 0;
}

int fs_rm(const char *path)
{
    uint32_t parent_inode;
    char filename[MAX_FILENAME_LENGTH];
    if (path_walk(path, &parent_inode, filename) != 0)
    {
        return -1;
    }
    uint32_t inode_id = find_inode_by_name(parent_inode, filename);
    if (inode_id == UINT32_MAX)
    {
        printf("No such file: %s\n", path);
        return -1;
    }
    struct Inode *inode = &g_inode_table[inode_id];
    if ((inode->mode & FS_FT_DIR) != 0)
    {
        printf("Is a directory: %s\n", path);
        return -1;
    }
    if (remove_dir_entry(parent_inode, filename) != 0)
    {
        return -1;
    }
    return 0;
}

int fs_cd(const char *path, char *current_path)
{
    uint32_t dir_inode;
    char filename[MAX_FILENAME_LENGTH];
    if (path_walk(path, &dir_inode, filename) != 0)
    {
        return -1;
    }
    uint32_t inode_id = find_inode_by_name(dir_inode, filename);
    if (inode_id == UINT32_MAX)
    {
        printf("No such file or directory: %s\n", path);
        return -1;
    }
    struct Inode *inode = &g_inode_table[inode_id];
    if ((inode->mode & FS_FT_DIR) == 0)
    {
        printf("Not a directory: %s\n", path);
        return -1;
    }

    g_cwd_inode = inode_id;

    if (build_path_from_inode(inode_id, current_path, 256) != 0)
    {
        // Fallback to root if error occurs
        strcpy(current_path, "/");
    }

    return 0;
}

int fs_ls(const char *path)
{
    // Special case for root directory
    if (strcmp(path, "/") == 0)
    {
        struct Inode *inode = &g_inode_table[1];
        uint32_t size = inode->size;
        uint32_t total_logical_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
        uint8_t block_buf[BLOCK_SIZE];

        for (uint32_t i = 0; i < total_logical_blocks; i++)
        {
            uint32_t physical_block_id = inode_get_or_create_block(inode, i, false);

            if (physical_block_id == 0)
            {
                continue;
            }
            if (read_block(physical_block_id, block_buf) != 0)
            {
                return UINT32_MAX;
            }
            uint32_t bytes_scanned = i * BLOCK_SIZE;
            uint32_t bytes_left = size - bytes_scanned;
            uint32_t scan_size = (bytes_left < BLOCK_SIZE) ? bytes_left : BLOCK_SIZE;

            for (uint32_t offset = 0; offset < scan_size; offset += sizeof(struct DirEntry))
            {
                struct DirEntry *entry = (struct DirEntry *)(block_buf + offset);
                if (entry->inode != 0)
                {
                    struct Inode *entry_inode = &g_inode_table[entry->inode];
                    printf("%s%s\n", entry->filename, (entry_inode->mode & FS_FT_DIR) ? "/" : "");
                }
            }
        }
        return 0;
    }

    uint32_t dir_inode;
    char filename[MAX_FILENAME_LENGTH];
    if (path_walk(path, &dir_inode, filename) != 0)
    {
        return -1;
    }
    uint32_t target_inode = dir_inode;
    if (filename[0] != '\0')
    {
        target_inode = find_inode_by_name(dir_inode, filename);
        if (target_inode == UINT32_MAX)
        {
            printf("No such file or directory: %s\n", path);
            return -1;
        }
    }
    struct Inode *inode = &g_inode_table[target_inode];
    uint32_t size = inode->size;
    uint32_t total_logical_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t block_buf[BLOCK_SIZE];

    for (uint32_t i = 0; i < total_logical_blocks; i++)
    {
        uint32_t physical_block_id = inode_get_or_create_block(inode, i, false);

        if (physical_block_id == 0)
        {
            continue;
        }
        if (read_block(physical_block_id, block_buf) != 0)
        {
            return UINT32_MAX;
        }
        uint32_t bytes_scanned = i * BLOCK_SIZE;
        uint32_t bytes_left = size - bytes_scanned;
        uint32_t scan_size = (bytes_left < BLOCK_SIZE) ? bytes_left : BLOCK_SIZE;

        for (uint32_t offset = 0; offset < scan_size; offset += sizeof(struct DirEntry))
        {
            struct DirEntry *entry = (struct DirEntry *)(block_buf + offset);
            if (entry->inode != 0)
            {
                struct Inode *entry_inode = &g_inode_table[entry->inode];
                printf("%s%s\n", entry->filename, (entry_inode->mode & FS_FT_DIR) ? "/" : "");
            }
        }
    }
    return 0;
}

int fs_lsof()
{
    printf("Open files:\n");
    for (int fd = 3; fd < MAX_OPEN_FILES; fd++)
    {
        if (g_fd_in_use[fd])
        {
            struct FileHandle *fh = &g_open_file_table[fd];
            char *filename = calloc(1, MAX_FILENAME_LENGTH);
            if (filename == NULL)
            {
                return -1;
            }
            if (find_name_by_inode(1, fh->inode_id, filename) != 0)
            {
                free(filename);
                return -1;
            }
            printf("FD: %d, Filename: %s, ", fd, filename);
            if(fh->mode & FS_O_READ)
            {
                printf("Mode: READ");
            }
            else if(fh->mode & FS_O_WRITE)
            {
                printf("Mode: WRITE");
            }
            else if(fh->mode & FS_O_RW)
            {
                printf("Mode: READ/WRITE");
            }
            else if(fh->mode & FS_O_APPEND)
            {
                printf("Mode: APPEND");
            }
            printf(", Offset: %u\n", fh->offset);
            free(filename);
        }
    }
    return 0;
}

// Helper function for fs_find
static void do_find_recursive(uint32_t dir_inode_id, const char *name)
{
    struct Inode *dir_inode = &g_inode_table[dir_inode_id];
    uint32_t size = dir_inode->size;
    uint32_t total_logical_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t block_buf[BLOCK_SIZE];

    for (uint32_t i = 0; i < total_logical_blocks; i++)
    {
        uint32_t physical_block_id = inode_get_or_create_block(dir_inode, i, false);
        if (physical_block_id == 0)
        {
            continue;
        }
        if (read_block(physical_block_id, block_buf) != 0)
        {
            continue;
        }

        uint32_t bytes_scanned = i * BLOCK_SIZE;
        uint32_t bytes_left = size - bytes_scanned;
        uint32_t scan_size = (bytes_left < BLOCK_SIZE) ? bytes_left : BLOCK_SIZE;

        for (uint32_t offset = 0; offset < scan_size; offset += sizeof(struct DirEntry))
        {
            struct DirEntry *entry = (struct DirEntry *)(block_buf + offset);
            if (entry->inode == 0)
            {
                continue;
            }
            if (strcmp(entry->filename, ".") == 0 || strcmp(entry->filename, "..") == 0)
            {
                continue;
            }

            if (strcmp(entry->filename, name) == 0)
            {
                char path_buf[512];
                struct Inode *entry_inode = &g_inode_table[entry->inode];
                if (entry_inode->mode & FS_FT_DIR)
                {
                    if (build_path_from_inode(entry->inode, path_buf, sizeof(path_buf)) == 0)
                    {
                        printf("%s/\n", path_buf);
                    }
                }
                else
                {
                    char parent_path[512];
                    if (build_path_from_inode(dir_inode_id, parent_path, sizeof(parent_path)) == 0)
                    {
                        size_t len = strlen(parent_path);
                        if (len == 1 && parent_path[0] == '/')
                        {
                            printf("/");
                        }
                        else
                        {
                            printf("%s/", parent_path);
                        }
                        printf("%s\n", entry->filename);
                    }
                }
            }
            if (g_inode_table[entry->inode].mode & FS_FT_DIR)
            {
                do_find_recursive(entry->inode, name);
            }
        }
    }
}

// Find a free file descriptor
static int find_free_fd()
{
    for (int i = 3; i < MAX_OPEN_FILES; i++)
    {
        if (!g_fd_in_use[i])
        {
            return i;
        }
    }
    return -1;
}

// Create blank inode and add entry to parent directory
static int create_inode_entry(uint32_t parent_inode_id, const char *name, uint16_t mode, uint32_t *new_inode_id)
{
    struct Inode *parent_inode = &g_inode_table[parent_inode_id];
    if ((parent_inode->mode & FS_FT_DIR) == 0)
    {
        return -1;
    }
    uint32_t inode_id = allocate_bitmap_bit(g_inode_bitmap, g_superblock->inode_count);
    if (inode_id == UINT32_MAX)
    {
        return -1;
    }
    g_superblock->free_inodes -= 1;

    struct Inode *inode = &g_inode_table[inode_id];
    memset(inode, 0, sizeof(struct Inode));
    inode->mode = mode;
    inode->uid = 0;
    inode->gid = 0;
    inode->size = 0;
    inode->block_count = 0;
    inode->ctime = (uint32_t)time(NULL);
    inode->mtime = inode->ctime;
    inode->atime = inode->ctime;

    if (add_dir_entry(parent_inode_id, name, inode_id) != 0)
    {
        clear_bitmap_bit(g_inode_bitmap, inode_id);
        return -1;
    }

    if (mode & FS_FT_DIR)
    {
        inode->link_count = 2;
        if (add_dir_entry(inode_id, ".", inode_id) != 0)
            return -1;
        if (add_dir_entry(inode_id, "..", parent_inode_id) != 0)
            return -1;
        parent_inode->link_count++;
        parent_inode->mtime = (uint32_t)time(NULL);
    }
    else
    {
        inode->link_count = 1;
    }

    *new_inode_id = inode_id;
    return 0;
}

// Help function help [create_inode_entry] to add dir entry
static int add_dir_entry(uint32_t dir_inode_id, const char *name, uint32_t target_inode_id)
{
    struct Inode *dir_inode = &g_inode_table[dir_inode_id];
    if ((dir_inode->mode & FS_FT_DIR) == 0)
    {
        return -1;
    }

    struct DirEntry entries[DIR_ENTRIES_PER_BLOCK];
    uint32_t logical_idx = 0;

    while (logical_idx < dir_inode->block_count)
    {
        uint32_t physical_block_id = inode_get_or_create_block(dir_inode, logical_idx, false);
        if (physical_block_id == UINT32_MAX)
        {
            return -1;
        }
        if (read_block(physical_block_id, (uint8_t *)entries) != 0)
        {
            return -1;
        }
        for (uint32_t i = 0; i < DIR_ENTRIES_PER_BLOCK; i++)
        {
            if (entries[i].inode == 0)
            {
                entries[i].inode = target_inode_id;
                strncpy(entries[i].filename, name, MAX_FILENAME_LENGTH - 1);
                entries[i].filename[MAX_FILENAME_LENGTH - 1] = '\0';
                if (write_block(physical_block_id, (uint8_t *)entries) != 0)
                {
                    return -1;
                }
                uint32_t new_size = (logical_idx * BLOCK_SIZE) + ((i + 1) * sizeof(struct DirEntry));
                if (new_size > dir_inode->size)
                {
                    dir_inode->size = new_size;
                }
                dir_inode->mtime = (uint32_t)time(NULL);
                return 0;
            }
        }
        logical_idx++;
    }

    uint32_t new_physical_block_id = inode_get_or_create_block(dir_inode, logical_idx, true);
    if (new_physical_block_id == UINT32_MAX)
    {
        return -1;
    }
    memset(entries, 0, BLOCK_SIZE);
    entries[0].inode = target_inode_id;
    strncpy(entries[0].filename, name, MAX_FILENAME_LENGTH - 1);
    entries[0].filename[MAX_FILENAME_LENGTH - 1] = '\0';

    if (write_block(new_physical_block_id, (uint8_t *)entries) != 0)
    {
        return -1;
    }
    dir_inode->block_count = logical_idx + 1;
    dir_inode->size = (logical_idx * BLOCK_SIZE) + sizeof(struct DirEntry);
    dir_inode->mtime = (uint32_t)time(NULL);
    return 0;
}

// Help function help [fs_rmdir], [fs_rm] to remove dir entry
static int remove_dir_entry(uint32_t parent_inode_id, const char *name)
{
    struct Inode *parent_inode = &g_inode_table[parent_inode_id];
    struct DirEntry entries[DIR_ENTRIES_PER_BLOCK];
    uint32_t total_blocks = (parent_inode->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint32_t i = 0; i < total_blocks; i++)
    {
        uint32_t physical_block_id = inode_get_or_create_block(parent_inode, i, false);
        if (physical_block_id == 0)
            continue;
        if (read_block(physical_block_id, (uint8_t *)entries) != 0)
        {
            return -1;
        }
        for (uint32_t j = 0; j < DIR_ENTRIES_PER_BLOCK; j++)
        {
            if (entries[j].inode != 0 && strcmp(entries[j].filename, name) == 0)
            {
                entries[j].inode = 0;
                memset(entries[j].filename, 0, sizeof(entries[j].filename));
                if (write_block(physical_block_id, (uint8_t *)entries) != 0)
                {
                    return -1;
                }
                parent_inode->mtime = (uint32_t)time(NULL);
                return 0;
            }
        }
    }
    return -1;
}

// Get the parent's inode and the last filename, whatever it is, please check the result
static int path_walk(const char *path, uint32_t *parent_inode, char *filename)
{
    if (path == NULL || path[0] == '\0')
    {
        return -1;
    }

    if (strcmp(path, "/") == 0)
    {
        *parent_inode = 1; // Root inode
        filename[0] = '\0';
        return 0;
    }

    uint32_t current_inode = (path[0] == '/') ? 1 : g_cwd_inode;

    char path_copy[MAX_PATH_LEN];
    strncpy(path_copy, path, MAX_PATH_LEN - 1);
    path_copy[MAX_PATH_LEN - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(path_copy, "/", &saveptr);
    char *next_token = NULL;

    if (token == NULL)
    {
        *parent_inode = 1;
        filename[0] = '\0';
        return 0;
    }

    while (token != NULL)
    {
        next_token = strtok_r(NULL, "/", &saveptr);

        if (next_token == NULL)
        {
            *parent_inode = current_inode;
            strncpy(filename, token, MAX_FILENAME_LENGTH - 1);
            filename[MAX_FILENAME_LENGTH - 1] = '\0';
            return 0;
        }

        uint32_t next_inode_id = find_inode_by_name(current_inode, token);
        if (next_inode_id == UINT32_MAX)
        {
            return -1;
        }

        if ((g_inode_table[next_inode_id].mode & FS_FT_DIR) == 0)
        {
            return -1;
        }

        current_inode = next_inode_id;
        token = next_token;
    }

    return -1;
}

// Find inode by [name] in a directory [inode] -> inode
static uint32_t find_inode_by_name(uint32_t inode, const char *name)
{
    struct Inode *dir_inode = &g_inode_table[inode];
    uint32_t size = dir_inode->size;
    uint32_t total_logical_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t block_buf[BLOCK_SIZE];
    for (uint32_t i = 0; i < total_logical_blocks; i++)
    {
        uint32_t physical_block_id = inode_get_or_create_block(dir_inode, i, false);

        if (physical_block_id == 0)
        {
            continue;
        }
        if (read_block(physical_block_id, block_buf) != 0)
        {
            return UINT32_MAX;
        }
        uint32_t bytes_scanned = i * BLOCK_SIZE;
        uint32_t bytes_left = size - bytes_scanned;
        uint32_t scan_size = (bytes_left < BLOCK_SIZE) ? bytes_left : BLOCK_SIZE;

        for (uint32_t offset = 0; offset < scan_size; offset += sizeof(struct DirEntry))
        {
            struct DirEntry *entry = (struct DirEntry *)(block_buf + offset);
            if (entry->inode != 0 && strcmp(entry->filename, name) == 0)
            {
                return entry->inode;
            }
        }
    }
    return UINT32_MAX;
}

// Find name by inode recursively from current_inode_id
static int find_name_by_inode(uint32_t current_inode_id, uint32_t target_inode_id, char *name_buf)
{
    struct Inode *dir_inode = &g_inode_table[current_inode_id];
    uint32_t size = dir_inode->size;
    uint32_t total_logical_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t block_buf[BLOCK_SIZE];

    for (uint32_t i = 0; i < total_logical_blocks; i++)
    {
        uint32_t physical_block_id = inode_get_or_create_block(dir_inode, i, false);

        if (physical_block_id == 0 || read_block(physical_block_id, block_buf) != 0)
        {
            continue;
        }

        uint32_t bytes_scanned = i * BLOCK_SIZE;
        uint32_t bytes_left = size - bytes_scanned;
        uint32_t scan_size = (bytes_left < BLOCK_SIZE) ? bytes_left : BLOCK_SIZE;

        for (uint32_t offset = 0; offset < scan_size; offset += sizeof(struct DirEntry))
        {
            struct DirEntry *entry = (struct DirEntry *)(block_buf + offset);
            if (entry->inode == 0)
            {
                continue;
            }
            if (strcmp(entry->filename, ".") == 0 || strcmp(entry->filename, "..") == 0)
            {
                continue;
            }
            if (entry->inode == target_inode_id)
            {
                strncpy(name_buf, entry->filename, MAX_FILENAME_LENGTH - 1);
                name_buf[MAX_FILENAME_LENGTH - 1] = '\0';
                return 0;
            }
            if (g_inode_table[entry->inode].mode & FS_FT_DIR)
            {
                if (find_name_by_inode(entry->inode, target_inode_id, name_buf) == 0)
                {
                    return 0;
                }
            }
        }
    }
    return -1;
}

// Get physical block id from inode and logical block index or allocate new block
static uint32_t inode_get_or_create_block(struct Inode *inode, uint32_t logical_idx, bool allocate)
{
    // Direct ptr
    if (logical_idx < DIRECT_PTRS)
    {
        if (inode->direct_blocks[logical_idx] == 0 && allocate)
        {
            inode->direct_blocks[logical_idx] = allocate_bitmap_bit(g_block_bitmap, g_superblock->block_count);
            if (inode->direct_blocks[logical_idx] == UINT32_MAX)
            {
                return UINT32_MAX;
            }
            g_superblock->free_blocks -= 1;
        }
        return inode->direct_blocks[logical_idx];
    }
    uint32_t block_id;
    uint32_t ptrs[PTRS_PER_BLOCK];
    logical_idx -= DIRECT_PTRS;

    // Indirect ptr
    if (logical_idx < PTRS_PER_BLOCK)
    {
        if (inode->indirect_block == 0)
        {
            if (!allocate)
            {
                return UINT32_MAX;
            }
            inode->indirect_block = allocate_bitmap_bit(g_block_bitmap, g_superblock->block_count);
            if (inode->indirect_block == UINT32_MAX)
            {
                return UINT32_MAX;
            }
            g_superblock->free_blocks -= 1;
            memset(ptrs, 0, BLOCK_SIZE);
            if (write_block(inode->indirect_block, (uint8_t *)ptrs) != 0)
            {
                return UINT32_MAX;
            }
        }
        else
        {
            if (read_block(inode->indirect_block, (uint8_t *)ptrs) != 0)
            {
                return UINT32_MAX;
            }
        }
        if (ptrs[logical_idx] == 0 && allocate)
        {
            block_id = allocate_bitmap_bit(g_block_bitmap, g_superblock->block_count);
            if (block_id == UINT32_MAX)
            {
                return UINT32_MAX;
            }
            g_superblock->free_blocks -= 1;
            ptrs[logical_idx] = block_id;
            if (write_block(inode->indirect_block, (uint8_t *)ptrs) != 0)
            {
                return UINT32_MAX;
            }
            return block_id;
        }
        return ptrs[logical_idx];
    }
    logical_idx -= PTRS_PER_BLOCK;

    // Double indirect ptr
    if (inode->double_indirect_block == 0)
    {
        if (!allocate)
        {
            return UINT32_MAX;
        }
        inode->double_indirect_block = allocate_bitmap_bit(g_block_bitmap, g_superblock->block_count);
        if (inode->double_indirect_block == UINT32_MAX)
        {
            return UINT32_MAX;
        }
        g_superblock->free_blocks -= 1;
        memset(ptrs, 0, BLOCK_SIZE);
        if (write_block(inode->double_indirect_block, (uint8_t *)ptrs) != 0)
        {
            return UINT32_MAX;
        }
    }
    else
    {
        if (read_block(inode->double_indirect_block, (uint8_t *)ptrs) != 0)
        {
            return UINT32_MAX;
        }
    }

    uint32_t level1_idx = logical_idx / PTRS_PER_BLOCK;
    uint32_t level2_idx = logical_idx % PTRS_PER_BLOCK;
    uint32_t indirect_blk = ptrs[level1_idx];
    if (indirect_blk == 0)
    {
        if (!allocate)
        {
            return UINT32_MAX;
        }
        indirect_blk = allocate_bitmap_bit(g_block_bitmap, g_superblock->block_count);
        if (indirect_blk == UINT32_MAX)
        {
            return UINT32_MAX;
        }
        g_superblock->free_blocks -= 1;

        ptrs[level1_idx] = indirect_blk;
        if (write_block(inode->double_indirect_block, (uint8_t *)ptrs) != 0)
        {
            return UINT32_MAX;
        }

        memset(ptrs, 0, BLOCK_SIZE);
        if (write_block(indirect_blk, (uint8_t *)ptrs) != 0)
        {
            return UINT32_MAX;
        }
    }
    else
    {
        if (read_block(indirect_blk, (uint8_t *)ptrs) != 0)
        {
            return UINT32_MAX;
        }
    }
    if (ptrs[level2_idx] == 0 && allocate)
    {
        block_id = allocate_bitmap_bit(g_block_bitmap, g_superblock->block_count);
        if (block_id == UINT32_MAX)
        {
            return UINT32_MAX;
        }
        g_superblock->free_blocks -= 1;
        ptrs[level2_idx] = block_id;
        if (write_block(indirect_blk, (uint8_t *)ptrs) != 0)
        {
            return UINT32_MAX;
        }
        return block_id;
    }
    return ptrs[level2_idx];
}

// Check if file duplicated
static int check_duplicate(const uint32_t parent_inode_id, const char *name)
{
    uint32_t check_inode = find_inode_by_name(parent_inode_id, name);
    if (check_inode != UINT32_MAX)
    {
        printf("%s already exists: %s\n", (g_inode_table[check_inode].mode & FS_FT_DIR) ? "Directory" : "File", name);
        return -1;
    }
    return 0;
}

// Build absolute path from inode
static int build_path_from_inode(uint32_t target_inode, char *path_buf, size_t buf_size)
{
    if (target_inode == 1)
    {
        strncpy(path_buf, "/", buf_size);
        return 0;
    }

    char temp_path[512] = "";
    uint32_t current = target_inode;

    while (current != 1)
    {
        struct Inode *dir = &g_inode_table[current];
        uint32_t parent_inode = 0;

        uint32_t size = dir->size;
        uint32_t total_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
        uint8_t block_buf[BLOCK_SIZE];

        for (uint32_t i = 0; i < total_blocks; i++)
        {
            uint32_t phys_block = inode_get_or_create_block(dir, i, false);
            if (phys_block == 0)
                continue;
            if (read_block(phys_block, block_buf) != 0)
                return -1;

            uint32_t scan_size = (size - i * BLOCK_SIZE < BLOCK_SIZE) ? (size - i * BLOCK_SIZE) : BLOCK_SIZE;

            for (uint32_t off = 0; off < scan_size; off += sizeof(struct DirEntry))
            {
                struct DirEntry *entry = (struct DirEntry *)(block_buf + off);
                if (entry->inode != 0 && strcmp(entry->filename, "..") == 0)
                {
                    parent_inode = entry->inode;
                    break;
                }
            }
            if (parent_inode != 0)
                break;
        }

        if (parent_inode == 0)
            return -1;

        char dirname[MAX_FILENAME_LENGTH] = "";
        if (find_name_by_inode(parent_inode, current, dirname) != 0)
        {
            return -1;
        }

        size_t new_len = strlen(dirname) + strlen(temp_path) + 2;
        if (new_len > sizeof(temp_path))
        {
            return -1;
        }

        char new_temp[512];
        strcpy(new_temp, "/");
        strcat(new_temp, dirname);
        strcat(new_temp, temp_path);
        strcpy(temp_path, new_temp);

        current = parent_inode;
    }

    if (temp_path[0] == '\0')
    {
        strncpy(path_buf, "/", buf_size);
    }
    else
    {
        strncpy(path_buf, temp_path, buf_size - 1);
        path_buf[buf_size - 1] = '\0';
    }

    return 0;
}

// Check if dir is empty
static bool is_dir_empty(const uint32_t dir_inode_id)
{
    struct Inode *dir_inode = &g_inode_table[dir_inode_id];
    uint32_t size = dir_inode->size;
    uint32_t total_logical_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t block_buf[BLOCK_SIZE];

    for (uint32_t i = 0; i < total_logical_blocks; i++)
    {
        uint32_t physical_block_id = inode_get_or_create_block(dir_inode, i, false);

        if (physical_block_id == 0)
        {
            continue;
        }
        if (read_block(physical_block_id, block_buf) != 0)
        {
            return false;
        }
        uint32_t bytes_scanned = i * BLOCK_SIZE;
        uint32_t bytes_left = size - bytes_scanned;
        uint32_t scan_size = (bytes_left < BLOCK_SIZE) ? bytes_left : BLOCK_SIZE;

        for (uint32_t offset = 0; offset < scan_size; offset += sizeof(struct DirEntry))
        {
            struct DirEntry *entry = (struct DirEntry *)(block_buf + offset);
            if (entry->inode != 0 && strcmp(entry->filename, ".") != 0 && strcmp(entry->filename, "..") != 0)
            {
                return false;
            }
        }
    }
    return true;
}