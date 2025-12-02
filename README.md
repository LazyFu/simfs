# SimFS

SimFS — A simple user-space file system simulator.

A minimal Unix-like file system implementation that runs entirely in user space, featuring inode-based storage, directory hierarchy, and file operations.

## Features

### File System Structure

- **Inode-based architecture** with direct, indirect, and double-indirect block pointers
- **Hierarchical directory structure** with `.` and `..` entries
- **Bitmap-based allocation** for inodes and data blocks
- **Superblock** containing file system metadata
- **Configurable block size** (default 4096 bytes)

### File Operations

- **File I/O**: Create, open, read, write, seek, and close files
- **Directory operations**: Create (`mkdir`), remove (`rmdir`), and change (`cd`) directories
- **File management**: Create and remove files
- **File descriptor management**: Track open files with `lsof`
- **Concurrency control**: Prevents conflicting file access

### Access Modes

- Read-only (`r`)
- Write-only (`w`)
- Read-write (`rw`)
- Append mode (`a`)

### File System Limits

- Maximum file size: ~4GB (through double-indirect blocks)
- Maximum open files: 32 concurrent file descriptors
- Maximum filename length: 28 characters

## Building

Run `make` to build the `mkfs` and `shell` utilities:

```bash
make
```

To clean build artifacts:

```bash
make clean
```

## Usage

### Creating a File System

Create the default file system image `simfs.img`:

```bash
./mkfs
```

Or create a file system image with a custom name:

```bash
./mkfs custom.img
```

### Running the Shell

Start the interactive shell on the default image:

```bash
./shell
```

Or specify a custom image file:

```bash
./shell custom.img
```

## Architecture

### Disk Layout

```txt
+----------------+
| Boot Block (0) |
+----------------+
| Superblock (1) |
+----------------+
| Inode Bitmap   |
+----------------+
| Block Bitmap   |
+----------------+
| Inode Table    |
+----------------+
| Data Blocks    |
+----------------+
```

### Inode Structure

Each inode contains:

- File metadata (mode, size, timestamps)
- 12 direct block pointers
- 1 indirect block pointer
- 1 double-indirect block pointer
- Link count and ownership information

### Directory Entry Format

Each directory entry is 32 bytes:

- Inode number (4 bytes)
- Filename (28 bytes, null-terminated)
