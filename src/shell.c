#include "fs_api.h"
#include "fs.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_COMMAND_LEN 256
#define MAX_ARGS 10

static char current_path[MAX_COMMAND_LEN] = "/";

void execute_command(char **args);
void print_shell_help();
void print_open_help();
void print_read_help();
void print_write_help();
void print_create_help();
void print_rmdir_help();

int main(int argc, char *argv[])
{
    char *disk_path = "simfs.img";
    if (argc == 2)
    {
        disk_path = argv[1];
    }
    if (fs_mount(disk_path) != 0)
    {
        printf("Failed to mount filesystem on %s\n", disk_path);
        return 1;
    }

    char cmd[256];
    printf("SimFS mounted\n");
    while (1)
    {
        printf("simfs:%s$ ", current_path);

        if (!fgets(cmd, sizeof(cmd), stdin))
        {
            break;
        }
        cmd[strcspn(cmd, "\n")] = 0;
        if (strlen(cmd) == 0)
        {
            continue;
        }
        char *args[MAX_ARGS];
        int arg_count = 0;
        char *token = strtok(cmd, " ");
        while (token != NULL && arg_count < MAX_ARGS - 1)
        {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
        args[arg_count] = NULL;

        if (arg_count > 0)
        {
            execute_command(args);
        }
    }
    if (fs_umount() != 0)
    {
        printf("Failed to unmount filesystem\n");
        return 1;
    }
    printf("SimFS successfully unmounted.\n");
    return 0;
}

void execute_command(char **args)
{
    const char *cmd = args[0];
    int result = 0;
    if (strcmp(cmd, "exit") == 0)
    {
        if (fs_umount() != 0)
        {
            printf("Error occurred during unmount.\n");
            exit(1);
        }
        printf("SimFS successfully unmounted.\n");
        exit(0);
    }

    if (strcmp(cmd, "open") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: open <file_path> <mode>\n");
            printf("Run \"open --help\" for mode details\n");
            return;
        }
        if (strcmp(args[1], "--help") == 0)
        {
            print_open_help();
            return;
        }
        uint16_t mode = FS_O_READ;
        if (args[2] == NULL)
        {
            mode = FS_O_READ;
        }
        else if (strcmp(args[2], "r") == 0)
        {
            mode = FS_O_READ;
        }
        else if (strcmp(args[2], "w") == 0)
        {
            mode = FS_O_WRITE;
        }
        else if (strcmp(args[2], "rw") == 0)
        {
            mode = FS_O_RW;
        }
        else if (strcmp(args[2], "a") == 0)
        {
            mode = FS_O_APPEND;
        }
        else
        {
            printf("Invalid mode: %s\n", args[2]);
            printf("Run \"open --help\" for mode details\n");
            return;
        }
        result = fs_open(args[1], mode);
    }
    else if (strcmp(cmd, "read") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: read <file_descriptor>\n");
            printf("Run \"read --help\" for details\n");
            return;
        }
        if (strcmp(args[1], "--help") == 0)
        {
            print_read_help();
            return;
        }
        int fd = atoi(args[1]);
        if (fd < 3)
        {
            printf("Invalid file descriptor: %d\n", fd);
            return;
        }
        char buffer[1025];
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = fs_read(fd, buffer, 1024);
        if (bytes_read > 0)
        {
            buffer[bytes_read] = '\0';
            printf("%s\n", buffer);
        }
        else if (bytes_read == 0)
        {
            printf("(end of file)\n");
        }
        result = (bytes_read >= 0) ? 0 : -1;
    }
    else if (strcmp(cmd, "write") == 0)
    {
        if (args[1] == NULL || args[2] == NULL)
        {
            printf("Usage: write <file descriptor> <data>\n");
            printf("Run \"write --help\" for details\n");
            return;
        }
        if (strcmp(args[1], "--help") == 0)
        {
            print_write_help();
            return;
        }
        int fd = atoi(args[1]);
        if (fd == 0 || fd == 1 || fd == 2)
        {
            printf("Usage: write <file descriptor> <data>\n");
            printf("Run \"write --help\" for details\n");
            return;
        }
        result = fs_write(fd, args[2], strlen(args[2]));
    }
    else if (strcmp(cmd, "seek") == 0)
    {
        if (args[1] == NULL || args[2] == NULL)
        {
            printf("Usage: seek <file_descriptor> <offset>\n");
            return;
        }
        int fd = atoi(args[1]);
        uint32_t offset = (uint32_t)atoi(args[2]);
        result = fs_seek(fd, offset);
    }
    else if (strcmp(cmd, "close") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: close <file_descriptor>\n");
            return;
        }
        int fd = atoi(args[1]);
        if (fd < 3)
        {
            printf("Cannot close standard file descriptors\n");
            return;
        }
        result = fs_close(fd);
    }
    else if (strcmp(cmd, "create") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: create <file_path>\n");
            printf("Run \"create --help\" for details\n");
            return;
        }
        if (strcmp(args[1], "--help") == 0)
        {
            print_create_help();
            return;
        }
        uint16_t mode = 644;
        if (args[2] != NULL)
        {
            int mode_input = atoi(args[2]);
            if (mode_input < 000 || mode_input > 777)
            {
                printf("Invalid mode: %s\n", args[2]);
                printf("Run \"create --help\" for details\n");
                return;
            }
            else
            {
                mode = (uint16_t)mode_input;
            }
        }
        result = fs_create(args[1], mode);
    }
    else if (strcmp(cmd, "mkdir") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: mkdir <directory_path>\n");
            printf("Run \"mkdir --help\" for details\n");
            return;
        }
        if (strcmp(args[1], "--help") == 0)
        {
            print_create_help();
            return;
        }
        uint16_t mode = 755;
        if (args[2] != NULL)
        {
            int mode_input = atoi(args[2]);
            if (mode_input < 000 || mode_input > 777)
            {
                printf("Invalid mode: %s\n", args[2]);
                printf("Run \"mkdir --help\" for details\n");
                return;
            }
            else
            {
                mode = (uint16_t)mode_input;
            }
        }
        result = fs_mkdir(args[1], mode);
    }
    else if (strcmp(cmd, "rmdir") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: rmdir <directory_path>\n");
            printf("Run \"rmdir --help\" for details\n");
            return;
        }
        result = fs_rmdir(args[1]);
    }
    else if (strcmp(cmd, "rm") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: rm <file_path>\n");
            return;
        }
        result = fs_rm(args[1]);
    }
    else if (strcmp(cmd, "cd") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: cd <directory>\n");
            return;
        }
        result = fs_cd(args[1], current_path);
    }
    else if (strcmp(cmd, "ls") == 0)
    {
        // If path argument provided, use it; otherwise use current_path
        const char *target_path = (args[1] != NULL) ? args[1] : current_path;
        result = fs_ls(target_path);
    }
    else if (strcmp(cmd, "lsof") == 0)
    {
        result = fs_lsof();
    }
    else if (strcmp(cmd, "find") == 0)
    {
        if (args[1] == NULL)
        {
            printf("Usage: find <filename>\n");
            return;
        }
        result = fs_find(args[1]);
    }
    else if (strcmp(cmd, "help") == 0)
    {
        print_shell_help();
    }
    else
    {
        printf("Unknown command: %s\n", cmd);
        printf("Type 'help' for a list of commands.\n");
        return;
    }
    if (result != 0)
    {
        printf("Command '%s' failed\n", cmd);
    }
}

void print_shell_help()
{
    printf("Available commands:\n");
    printf("  open <file_path> [mode]    - Open a file with specified mode (r, w, rw, a), default read-only (r)\n");
    printf("  read <file_descriptor>     - Read from an open file and print content\n");
    printf("  write <file_descriptor> <data> - Write data to an open file\n");
    printf("  seek <file_descriptor> <offset> - Move file offset to specified position\n");
    printf("  close <file_descriptor>    - Close an open file\n");
    printf("  create <file_path> [mode]  - Create a new file with optional mode (default 644)\n");
    printf("  mkdir <directory_path> [mode] - Create a new directory with optional mode (default 755)\n");
    printf("  rmdir <directory_path>     - Remove an empty directory\n");
    printf("  rm <file_path>             - Remove a file\n");
    printf("  cd <directory>             - Change current directory\n");
    printf("  ls [path]                  - List files in current or specified directory\n");
    printf("  find <filename>            - Find by name from current directory and print paths\n");
    printf("  lsof                       - List open files\n");
    printf("  help                       - Show this help message\n");
    printf("  exit                       - Exit the shell\n");
}

void print_open_help()
{
    printf("Usage: open <file_path> [mode]\n");
    printf("Open a file with the specified mode.\n");
    printf("Modes:\n");
    printf("  r   - Read-only (default)\n");
    printf("  w   - Write-only\n");
    printf("  rw  - Read and write\n");
    printf("  a   - Append mode\n");
}

void print_read_help()
{
    printf("Usage: read <file_descriptor>\n");
    printf("Read from an open file specified by the file descriptor.\n");
    printf("Reads up to 1024 bytes or until end of file.\n");
    printf("The file must be opened first (use 'open' command).\n");
    printf("Run \"lsof\" to see opened file descriptors.\n");
    printf("Tip: Use 'seek' to move the file offset before reading.\n");
}

void print_write_help()
{
    printf("Usage: write <file_descriptor> <data>\n");
    printf("Write data to an **open** file specified by the file descriptor.\n");
    printf("You should open it first.\n");
    printf("Run \"lsof\" to see opened file descriptors.\n");
}

void print_create_help()
{
    printf("Usage: create <file_path> [mode]\n");
    printf("Create a new file with the specified mode (permissions), numberic only.\n");
    printf("Example modes:\n");
    printf("  644 - Owner read/write, group read, others read\n");
    printf("  755 - Owner read/write/execute, group read/execute, others read/execute\n");
}

void print_mkdir_help()
{
    printf("Usage: mkdir <directory_path> [mode]\n");
    printf("Create a new directory with the specified mode (permissions), numeric only.\n");
    printf("Example modes:\n");
    printf("  755 - Owner read/write/execute, group read/execute, others read/execute\n");
}

void print_rmdir_help()
{
    printf("Usage: rmdir <directory_path>\n");
    printf("Remove an **empty** directory specified by the path.\n");
}