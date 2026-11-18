/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* The file systems of a dump read in place (snx_hac.h), dispatched through the ops each kind of container fills in:
   hactool's NCAs (snx_hac.c), or a NUP's virtual image (driver/nup.c). The caller reads either the same way */
#include "snx_hac.h"

void snx_hac_fs_free(SnxHacFs *fs) {
    if (fs) fs->ops->close(fs);
}

size_t snx_hac_fs_files(SnxHacFs *fs, const SnxHacEntry **files) { return fs->ops->files(fs, files); }

int snx_hac_fs_read(SnxHacFs *fs, size_t file, uint64_t offset, void *buffer, size_t size) {
    return fs->ops->read(fs, file, offset, buffer, size);
}

uint64_t snx_hac_fs_romfs_size(const SnxHacFs *fs) { return fs->ops->romfs_size(fs); }

int snx_hac_fs_read_romfs(SnxHacFs *fs, uint64_t offset, void *buffer, size_t size) {
    return fs->ops->read_romfs(fs, offset, buffer, size);
}
