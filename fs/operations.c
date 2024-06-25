#include "operations.h"
#include "config.h"
#include "state.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


#include "betterassert.h"

static pthread_mutex_t data_blocks_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t inode_access_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t file_allocation_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t offset_updates_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t directory_updates_mutex = PTHREAD_MUTEX_INITIALIZER;

tfs_params tfs_default_params() {
    tfs_params params = {
        .max_inode_count = 64,
        .max_block_count = 1024,
        .max_open_files_count = 16,
        .block_size = 1024,
    };
    return params;
}

int tfs_init(tfs_params const *params_ptr) {
    tfs_params params;
    if (params_ptr != NULL) {
        params = *params_ptr;
    } else {
        params = tfs_default_params();
    }

    if (state_init(params) != 0) {
        return -1;
    }

    // create root inode
    pthread_mutex_lock(&inode_access_mutex);
    int root = inode_create(T_DIRECTORY);
    pthread_mutex_unlock(&inode_access_mutex);
    if (root != ROOT_DIR_INUM) {
        return -1;
    }

    return 0;
}

int tfs_destroy() {
    if (state_destroy() != 0) {
        return -1;
    }
    return 0;
}

static bool valid_pathname(char const *name) {
    return name != NULL && strlen(name) > 1 && name[0] == '/';
}

/**
 * Looks for a file.
 *
 * Note: as a simplification, only a plain directory space (root directory only)
 * is supported.
 *
 * Input:
 *   - name: absolute path name
 *   - root_inode: the root directory inode
 * Returns the inumber of the file, -1 if unsuccessful.
 */
static int tfs_lookup(char const *name, inode_t const *root_inode) {
    // TODO: assert that root_inode is the root directory
    if (!valid_pathname(name)) {
        return -1;
    }

    // skip the initial '/' character
    name++;

    return find_in_dir(root_inode, name);
}

int tfs_open(char const *name, tfs_file_mode_t mode) {
    // Checks if the path name is valid
    if (!valid_pathname(name)) {
        return -1;
    }
    pthread_mutex_lock(&inode_access_mutex);
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    pthread_mutex_unlock(&inode_access_mutex);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                  "tfs_open: root dir inode must exist");
    int inum = tfs_lookup(name, root_dir_inode);
    size_t offset;

    if (inum >= 0) {
        // The file already exists
        pthread_mutex_lock(&inode_access_mutex);
        inode_t *inode = inode_get(inum);
        pthread_mutex_unlock(&inode_access_mutex);
        ALWAYS_ASSERT(inode != NULL,
                      "tfs_open: directory files must have an inode");
        if (inode->i_node_type == T_SYMLINK) {
            // Handle symbolic link: retrieve target of symbolic link and look up inode number of target file
            char const *target;
            pthread_mutex_lock(&data_blocks_mutex);
            target = data_block_get(inode->i_data_block);
            pthread_mutex_unlock(&data_blocks_mutex);
            inum = tfs_lookup(target, root_dir_inode);
            if (inum == -1) return -1;
            // Retrieve inode of target file
            pthread_mutex_lock(&inode_access_mutex);
            inode = inode_get(inum);
            pthread_mutex_unlock(&inode_access_mutex);
            // Ensure that inode of target file exists
            ALWAYS_ASSERT(inode != NULL,
                      "tfs_open: directory files must have an inode");
            // Set initial offset to end of target file
            offset = inode->i_size;
        }

        //Truncate (if requested)
        if (mode & TFS_O_TRUNC) {
            if (inode->i_size > 0) {
                pthread_mutex_lock(&data_blocks_mutex);
                data_block_free(inode->i_data_block);
                pthread_mutex_unlock(&data_blocks_mutex);
                inode->i_size = 0;
            }
        }
        // Determine initial offset
        if (mode & TFS_O_APPEND) {
            offset = inode->i_size;
        } else {
            offset = 0;
        }
    } else if (mode & TFS_O_CREAT) {
        // The file does not exist; the mode specified that it should be created
        // Create inode
        pthread_mutex_lock(&inode_access_mutex);
        inum = inode_create(T_FILE);
        pthread_mutex_unlock(&inode_access_mutex);
        if (inum == -1) {
            return -1; // no space in inode table
        }

        // Add entry in the root directory
        pthread_mutex_lock(&directory_updates_mutex);
        if (add_dir_entry(root_dir_inode, name + 1, inum) == -1) {
            pthread_mutex_lock(&inode_access_mutex);
            inode_delete(inum);
            pthread_mutex_unlock(&inode_access_mutex);
            return -1; // no space in directory
        }
        pthread_mutex_unlock(&directory_updates_mutex);

        offset = 0;
    } else {
        return -1;
    }

    // Finally, add entry to the open file table and return the corresponding
    // handle
    return add_to_open_file_table(inum, offset);

    // Note: for simplification, if file was created with TFS_O_CREAT and there
    // is an error adding an entry to the open file table, the file is not
    // opened but it remains created
}


int tfs_sym_link(char const *target, char const *link_name) {
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM); // Retrieve root directory inode
    ALWAYS_ASSERT(root_dir_inode != NULL, 
                    "tfs_sym_link: root dir inode must exist"); // Ensure that root directory inode exists

    // Check if path names are valid
    if(!valid_pathname(link_name))
        return -1;

    // Check if target file exists
    if(!tfs_lookup(target, root_dir_inode))
        return -1;

    // Create symbolic link inode
    pthread_mutex_lock(&inode_access_mutex);
    int inum = inode_create(T_SYMLINK);
    if (inum == -1) return -1;
    inode_t *inode = inode_get(inum);
    pthread_mutex_unlock(&inode_access_mutex);

     // Allocate data block for symbolic link
    pthread_mutex_lock(&data_blocks_mutex);
    int data_block = data_block_alloc();
    pthread_mutex_unlock(&data_blocks_mutex);
    if (data_block == -1) return -1;

    // Store target in symbolic link's data block
    size_t target_size = sizeof(target);
    pthread_mutex_lock(&inode_access_mutex);
    inode->i_size = target_size;
    inode->i_data_block = data_block;
    pthread_mutex_unlock(&inode_access_mutex);
    pthread_mutex_lock(&data_blocks_mutex);
    memcpy(data_block_get(data_block), target, target_size);
    pthread_mutex_unlock(&data_blocks_mutex);
    

    // Add symbolic link to root directory
    pthread_mutex_lock(&directory_updates_mutex);
    if (add_dir_entry(root_dir_inode, link_name + 1, inum) == -1)
        return -1;
    pthread_mutex_unlock(&directory_updates_mutex);

    return 0;
}

int tfs_link(char const *target, char const *link_name) {
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM); // Retrieve root directory inode
    ALWAYS_ASSERT(root_dir_inode != NULL,
            "tfs_sym_link: root dir inode must exist"); // Ensure that root directory inode exists

    if (!valid_pathname(link_name)) // Check if path names are valid
        return -1;

    int target_inode = tfs_lookup(target, root_dir_inode); // Look up inode number of target file
    if (target_inode == -1)  return -1;

    pthread_mutex_lock(&inode_access_mutex);
    inode_t *inode = inode_get(target_inode); // Retrieve target inode
    pthread_mutex_unlock(&inode_access_mutex);

    if (inode->i_node_type == T_SYMLINK) // Return error if target is a symbolic link
        return -1;

    pthread_mutex_lock(&directory_updates_mutex);
    if (add_dir_entry(root_dir_inode, link_name + 1, target_inode) == -1) // Add hard link to root directory
        return -1;
    pthread_mutex_unlock(&directory_updates_mutex);

    pthread_mutex_lock(&inode_access_mutex);
    inode->hard_link_count++;  // Increment hard link count of target inode
    pthread_mutex_unlock(&inode_access_mutex);
    return 0;
}

int tfs_close(int fhandle) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1; // invalid fd
    }
    pthread_mutex_lock(&file_allocation_mutex);
    remove_from_open_file_table(fhandle);
    pthread_mutex_unlock(&file_allocation_mutex);

    return 0;
}

ssize_t tfs_write(int fhandle, void const *buffer, size_t to_write) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    //  From the open file table entry, we get the inode
    pthread_mutex_lock(&inode_access_mutex);
    inode_t *inode = inode_get(file->of_inumber);
    pthread_mutex_unlock(&inode_access_mutex);
    ALWAYS_ASSERT(inode != NULL, "tfs_write: inode of open file deleted");

    // Determine how many bytes to write
    size_t block_size = state_block_size();
    if (to_write + file->of_offset > block_size) {
        to_write = block_size - file->of_offset;
    }

    if (to_write > 0) {
        if (inode->i_size == 0) {
            // If empty file, allocate new block
            pthread_mutex_lock(&data_blocks_mutex);
            int bnum = data_block_alloc();
            pthread_mutex_unlock(&data_blocks_mutex);
            if (bnum == -1) {
                return -1; // no space
            }
            pthread_mutex_lock(&inode_access_mutex);
            inode->i_data_block = bnum;
            pthread_mutex_unlock(&inode_access_mutex);
        }
        pthread_mutex_lock(&data_blocks_mutex);
        void *block = data_block_get(inode->i_data_block);
        pthread_mutex_unlock(&data_blocks_mutex);
        ALWAYS_ASSERT(block != NULL, "tfs_write: data block deleted mid-write");

        // Perform the actual write
        pthread_mutex_lock(&offset_updates_mutex);
        memcpy(block + file->of_offset, buffer, to_write);
        pthread_mutex_unlock(&offset_updates_mutex);

        // The offset associated with the file handle is incremented accordingly
        pthread_mutex_lock(&offset_updates_mutex);
        file->of_offset += to_write;
        pthread_mutex_unlock(&offset_updates_mutex);
        if (file->of_offset > inode->i_size) {
            pthread_mutex_lock(&inode_access_mutex);
            inode->i_size = file->of_offset;
            pthread_mutex_unlock(&inode_access_mutex);
        }
    }

    return (ssize_t)to_write;
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    // From the open file table entry, we get the inode
    pthread_mutex_lock(&inode_access_mutex);
    inode_t const *inode = inode_get(file->of_inumber);
    pthread_mutex_unlock(&inode_access_mutex);
    ALWAYS_ASSERT(inode != NULL, "tfs_read: inode of open file deleted");

    // Determine how many bytes to read
    size_t to_read = inode->i_size - file->of_offset;
    if (to_read > len) {
        to_read = len;
    }

    if (to_read > 0) {
        pthread_mutex_lock(&data_blocks_mutex);
        void *block = data_block_get(inode->i_data_block);
        pthread_mutex_unlock(&data_blocks_mutex);
        ALWAYS_ASSERT(block != NULL, "tfs_read: data block deleted mid-read");

        // Perform the actual read
        pthread_mutex_lock(&data_blocks_mutex);
        memcpy(buffer, block + file->of_offset, to_read);
        pthread_mutex_unlock(&data_blocks_mutex);
        // The offset associated with the file handle is incremented accordingly
        pthread_mutex_lock(&offset_updates_mutex);
        file->of_offset += to_read;
        pthread_mutex_unlock(&offset_updates_mutex);
    }

    return (ssize_t)to_read;
}

int tfs_unlink(char const *target) {
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM); // Retrieve root directory inode
    ALWAYS_ASSERT(root_dir_inode != NULL,
            "tfs_sym_link: root dir inode must exist"); // Ensure that root directory inode exists

    int target_inode = tfs_lookup(target, root_dir_inode);  // Look up inode number of target file or symbolic link
    if (target_inode == -1)  return -1;

    pthread_mutex_lock(&directory_updates_mutex);
    if (clear_dir_entry(root_dir_inode, target + 1) == - 1) // Remove target from root directory
        return -1;
    pthread_mutex_unlock(&directory_updates_mutex);

    pthread_mutex_lock(&inode_access_mutex);
    inode_t *inode = inode_get(target_inode);  // Retrieve target inode
    pthread_mutex_unlock(&inode_access_mutex);

    
    // Decrement hard link count and delete inode if no more hard links remain
    pthread_mutex_lock(&inode_access_mutex);
    if (inode->hard_link_count <= 0)
        inode_delete(target_inode);
    else inode->hard_link_count--;
    pthread_mutex_unlock(&inode_access_mutex);

    return 0;
}

int tfs_copy_from_external_fs(char const *source_path, char const *dest_path) {
    // Allocate buffer for reading and writing file contents
    size_t BUFFER_SIZE = state_block_size();
    char buffer[BUFFER_SIZE];
    size_t elementsRead;

     // Open destination file in virtual file system
    int fhandle = tfs_open(dest_path, TFS_O_TRUNC| TFS_O_CREAT);
    if (fhandle == -1) {
        return -1;
    }

     // Open source file in external file system
    FILE *sourceFile = fopen(source_path, "r");
    if (sourceFile == NULL) {
        tfs_close(fhandle);
        return -1;
    }

    // Read file contents from source and write to destination in blocks
    while ((elementsRead = fread(buffer, sizeof(char), BUFFER_SIZE, sourceFile)) > 0){
        if (tfs_write(fhandle, buffer, elementsRead) != elementsRead){
            tfs_close(fhandle);
            fclose(sourceFile);
            return -1;
        }
    }

     // Close files and return success
    tfs_close(fhandle);
    fclose(sourceFile);
    return 0;
}