#include "../fs/operations.h"
#include <assert.h>
#include <stdio.h>

int main() {
    assert(tfs_init(NULL) != -1);

    // invalid file path for the external file
    char *path = "/this_file_doesnt_even_exist";

    // test tfs_copy_from_external_fs with invalid file path
    int ret = tfs_copy_from_external_fs(path, "/f1");
    assert(ret == -1);

    // invalid path name (not an absolute path name)
    path = "f3";

    // test tfs_open with invalid path name
    int f = tfs_open(path, TFS_O_CREAT);
    assert(f == -1);

    // file path that points to a file that is too large to fit in the file system
    path = "/this_is_a_large_file";

    // test tfs_copy_from_external_fs with file that is too large to fit in the file system
    ret = tfs_copy_from_external_fs(path, "/f1");
    assert(ret == -1);

    printf("Successful test.\n");
    return 0;
}