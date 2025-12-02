#include <stdint.h>
#include <stdbool.h>

#define MAX_OPEN_FILES 32
#define FS_O_READ 0x1   // READ only
#define FS_O_WRITE 0x2  // WRITE only
#define FS_O_RW 0x4     // READ and WRITE
#define FS_O_APPEND 0x8 // APPEND mode

struct FileHandle
{
    uint32_t inode_id; // inode
    uint32_t offset;   // file ptr offset
    uint16_t mode;     // access mode
    bool is_dirty;     // whether the file content has been modified
};

struct FileConcurrency
{
    uint32_t readers; // number of readers
    uint32_t writers; // number of writers
};

int fs_mount(const char *disk_name);
int fs_umount();
int fs_open(const char *path, uint16_t mode);
int fs_read(int fd, void *buf, uint32_t count);
int fs_write(int fd, const void *buf, uint32_t count);
int fs_close(int fd);
int fs_seek(int fd, uint32_t offset);
int fs_create(const char *path, uint16_t mode);
int fs_mkdir(const char *path, uint16_t mode);
int fs_rmdir(const char *path);
int fs_rm(const char *path);
int fs_cd(const char *path, char *output_path);
int fs_ls(const char *path);
int fs_lsof();
