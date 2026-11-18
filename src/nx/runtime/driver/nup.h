/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* A NUP container (the NUP format's SPEC.md, version 1) read in place: unencrypted ExeFS and full RomFS trees of a
   game's base, updates and add-on content in one .nup file, no keys and no extraction. The reader validates the whole
   table of contents before it trusts a value of it, and serves a package's RomFS as a virtual flat image through
   SnxHacFs (hactool/snx_hac.h), which the runtime reads as it reads a dump's */
#ifndef SNX_NUP_H
#define SNX_NUP_H

#include "common/utilities/common.h"
#include "nx/runtime/driver/hactool/snx_hac.h"

typedef struct SnxNup SnxNup;

/* 1 when path starts with the NUP superblock's magic (NUP\x01), else 0, saying nothing */
int snx_nup_magic(const char* path);
/* path opened and its whole table of contents validated (SPEC 6.1): 0 with *nup set, else -1, said why. snx_nup_close
   either way. The packages' meta blocks are read with it; file content is checked against its SHA-256 as it is read */
int snx_nup_open(SnxNup** nup, const char* path);
void snx_nup_close(SnxNup* nup);
size_t snx_nup_count(const SnxNup* nup);
SnxU64 snx_nup_title(const SnxNup* nup, size_t pkg);
SnxU32 snx_nup_version(const SnxNup* nup, size_t pkg);
/* the package's kind: 0 base, 1 update, 2 add-on content (3 and 4 are refused at open) */
int snx_nup_kind(const SnxNup* nup, size_t pkg);
/* the first package of kind and title_id (0 for any of that kind): its index, or -1 for none */
int snx_nup_find(const SnxNup* nup, int kind, SnxU64 title_id);
/* the update of the highest version (an opaque u32, SPEC 3.1.1): its index, or -1 without one */
int snx_nup_newest_update(const SnxNup* nup);
/* the package's meta TLV of type (SPEC 5: 1 NPDM, 2 NACP, 3 icon, ...), malloc'd into *size bytes, or NULL without
   one */
unsigned char* snx_nup_meta(const SnxNup* nup, size_t pkg, unsigned type, size_t* size);
/* the package's ExeFS and RomFS as a file system read in place (SnxHacFs), base_pkg >= 0 laying the base's trees under
   the package's (an update over its base: its files shadow the base's per path, the base's others survive), -1 for the
   package alone (a base, or an add-on). NULL, said why, when its trees cannot be laid out */
SnxHacFs* snx_nup_fs(SnxNup* nup, size_t pkg, int base_pkg);

#endif
