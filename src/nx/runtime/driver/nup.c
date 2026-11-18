/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* A NUP container read in place (nup.h, the NUP format's SPEC.md v1). The table of contents is read whole and checked
   against its SHA-256 before any value of it is trusted; every record's bounds, the tree's shape and the extents'
   layout are validated once at open. A package's RomFS is served as a virtual flat image: its tables synthesized in
   memory (the layout fs.c's romfs_build makes, which the runtime's image reader expects), its file data read lazily
   from the blob's extents through a bounded LRU cache, each extent checked against its SHA-256 once as it is filled.
   No extraction and no copy: a 9 GB container is read where it lies */
#include "nx/runtime/driver/nup.h"
#include "common/utilities/endian.h"
#include "common/platform/file.h"
#include <openssl/evp.h>
#include <zstd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUP_NONE 0xFFFFFFFFu
#define NUP_CACHE_BUDGET (256ull << 20) /* the decompressed bytes the cache holds at most */
#define NUP_CACHE_ENTRY_MAX (64ull << 20) /* a bigger extent is streamed, not held whole */
#define NUP_CACHE_SLOTS 1024
#define NUP_IO (64u << 10)
#define NUP_DEPTH_MAX 256 /* as fs.c's image reader: a deeper tree is refused */

typedef struct {
    SnxU64 key;  /* the extent's offset, 0 for a free slot (a real extent lies past the blob's start) */
    SnxU64 size; /* the uncompressed bytes data holds */
    SnxU64 used; /* the LRU clock */
    unsigned char* data;
    int bad; /* its SHA-256 did not match: every read of it fails */
} NupExtent;

/* one oversized extent streamed at a time (the callers serialize, fs.c's dlock): a read past where it stands restarts
   it, which a zstd extent can only be read from its start */
typedef struct {
    SnxU64 extent, size; /* the extent streamed, 0 for none, and its uncompressed size */
    SnxU64 out_at;       /* the bytes produced so far */
    SnxU64 in_at, in_end; /* the input's next byte and end, absolute */
    int codec, verified, bad, ended;
    ZSTD_DCtx* z;
    EVP_MD_CTX* sha;
    unsigned char in[NUP_IO];
    size_t in_pos, in_size;
} NupStream;

struct SnxNup {
    FILE* file;
    char* path;
    unsigned char* toc; /* the whole table of contents, its SHA-256 checked */
    SnxU64 toc_size, blob_offset, file_size;
    SnxU64 packages_off, dirs_off, files_off, children_off, pool_off, pool_size;
    SnxU32 package_count, dir_count, file_count, child_count;
    unsigned char* meta; /* one block: meta_at[package_count] (offsets into it), then the meta bytes at meta_data */
    SnxU64 meta_data;
    NupExtent* cache;
    SnxU64 cache_bytes, cache_clock;
    NupStream stream;
};

/* ------------------------------------------------------------------ records, little-endian in the TOC */

static SnxU32 ld32(const unsigned char* p) { return snx_ld_le32(p); }
static SnxU64 ld64(const unsigned char* p) { return snx_ld_le64(p); }
static SnxU32 ld16(const unsigned char* p) { return (SnxU32)p[0] | ((SnxU32)p[1] << 8); }

static const unsigned char* prec(const SnxNup* n, size_t i) { return n->toc + n->packages_off + i * 0x40; }
static const unsigned char* drec(const SnxNup* n, SnxU32 i) { return n->toc + n->dirs_off + (SnxU64)i * 0x18; }
static const unsigned char* frec(const SnxNup* n, SnxU32 i) { return n->toc + n->files_off + (SnxU64)i * 0x50; }
static SnxU32 child_id(const SnxNup* n, SnxU32 slot) { return ld32(n->toc + n->children_off + (SnxU64)slot * 4); }
static const unsigned char* name_ptr(const SnxNup* n, SnxU32 off) { return n->toc + n->pool_off + off; }

static SnxU64 pkg_title(const SnxNup* n, size_t i) { return ld64(prec(n, i)); }
static SnxU32 pkg_version(const SnxNup* n, size_t i) { return ld32(prec(n, i) + 0x14); }
static unsigned pkg_kind(const SnxNup* n, size_t i) { return prec(n, i)[0x18]; }
static SnxU32 pkg_dir(const SnxNup* n, size_t i, unsigned off) { return ld32(prec(n, i) + off); }

/* a name is a label, never a path (SPEC 6.1): no separator, no NUL, no dot directory. A folder's may be empty (the
   root); a file's may not */
static int name_ok(const unsigned char* p, SnxU32 len, int is_file) {
    if (memchr(p, '/', len) || memchr(p, 0, len)) return 0;
    if (is_file && !len) return 0;
    if ((len == 1 && p[0] == '.') || (len == 2 && p[0] == '.' && p[1] == '.')) return 0;
    return 1;
}
static int name_cmp(const unsigned char* a, SnxU32 alen, const unsigned char* b, SnxU32 blen) {
    SnxU32 n = alen < blen ? alen : blen;
    int c = memcmp(a, b, n);
    return c ? c : (alen < blen ? -1 : alen > blen ? 1 : 0);
}
/* the dump-tool artifacts a producer may have kept (SPEC 6.3), which are no game files */
static int artifact(const unsigned char* p, SnxU32 len) { return len == 8 && !memcmp(p, ".listing", 8); }

static int badf(SnxNup* n, const char* fmt, ...) {
    char why[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, sizeof why, fmt, ap);
    va_end(ap);
    return snx_error("%s: %s", n->path, why);
}

/* ------------------------------------------------------------------ the reader */

static SnxU64 meta_at(const SnxNup* n, size_t pkg) { return ((const SnxU64*)n->meta)[pkg]; }

int snx_nup_magic(const char* path) {
    unsigned char magic[4];
    FILE* f = path ? snx_fopen(path, "rb") : NULL;
    int yes;
    if (!f) return 0;
    yes = fread(magic, 1, 4, f) == 4 && !memcmp(magic, "NUP\x01", 4);
    fclose(f);
    return yes;
}

void snx_nup_close(SnxNup* n) {
    if (!n) return;
    if (n->cache)
        for (size_t i = 0; i < NUP_CACHE_SLOTS; i++) free(n->cache[i].data);
    free(n->cache);
    if (n->stream.z) ZSTD_freeDCtx(n->stream.z);
    if (n->stream.sha) EVP_MD_CTX_free(n->stream.sha);
    free(n->meta);
    free(n->toc);
    free(n->path);
    if (n->file) fclose(n->file);
    free(n);
}

size_t snx_nup_count(const SnxNup* n) { return n->package_count; }
SnxU64 snx_nup_title(const SnxNup* n, size_t pkg) { return pkg_title(n, pkg); }
SnxU32 snx_nup_version(const SnxNup* n, size_t pkg) { return pkg_version(n, pkg); }
int snx_nup_kind(const SnxNup* n, size_t pkg) { return (int)pkg_kind(n, pkg); }

int snx_nup_find(const SnxNup* n, int kind, SnxU64 title_id) {
    for (size_t i = 0; i < n->package_count; i++)
        if (pkg_kind(n, i) == (unsigned)kind && (!title_id || pkg_title(n, i) == title_id)) return (int)i;
    return -1;
}

int snx_nup_newest_update(const SnxNup* n) {
    int at = -1;
    SnxU32 best = 0;
    for (size_t i = 0; i < n->package_count; i++)
        if (pkg_kind(n, i) == 1 && (at < 0 || pkg_version(n, i) > best)) {
            at = (int)i;
            best = pkg_version(n, i);
        }
    return at;
}

/* the package's meta TLV of type: 1 with its payload's offset in n->meta and size, 0 without one */
static int meta_find(const SnxNup* n, size_t pkg, unsigned type, SnxU64* off, SnxU32* size) {
    SnxU64 at = meta_at(n, pkg);
    SnxU32 left = ld32(prec(n, pkg) + 0x28);
    if (at == ~(SnxU64)0) return 0;
    while (left >= 8) {
        const unsigned char* t = n->meta + at;
        SnxU32 n_size = ld32(t + 4);
        if (n_size > left - 8) return 0;
        if (ld16(t) == type) {
            *off = at + 8;
            *size = n_size;
            return 1;
        }
        at += 8 + n_size;
        left -= 8 + n_size;
    }
    return 0;
}

unsigned char* snx_nup_meta(const SnxNup* n, size_t pkg, unsigned type, size_t* size) {
    SnxU64 off;
    SnxU32 n_size;
    unsigned char* out;
    *size = 0;
    if (!meta_find(n, pkg, type, &off, &n_size)) return NULL;
    out = (unsigned char*)malloc(n_size ? n_size : 1);
    if (out) {
        memcpy(out, n->meta + off, n_size);
        *size = n_size;
    }
    return out;
}

/* ------------------------------------------------------------------ validation (SPEC 6.1) */

typedef struct {
    SnxU64 off, size;
    SnxU32 idx;
    unsigned char meta; /* a package's meta block, else a file's extent */
} Region;

static int region_cmp(const void* a, const void* b) {
    const Region* x = (const Region*)a;
    const Region* y = (const Region*)b;
    if (x->off != y->off) return x->off < y->off ? -1 : 1;
    if (x->size != y->size) return x->size < y->size ? -1 : 1;
    return 0;
}

static int sha_ok(const unsigned char* data, SnxU64 size, const unsigned char* sha) {
    unsigned char dig[32];
    unsigned len = 0;
    return EVP_Digest(data, (size_t)size, dig, &len, EVP_sha256(), NULL) && len == 32 && !memcmp(dig, sha, 32);
}

int snx_nup_open(SnxNup** out, const char* path) {
    SnxNup* n = (SnxNup*)calloc(1, sizeof *n);
    unsigned char sb[0x80];
    SnxU64 actual, hsize, toc_off, blob, fsize, need, pool_off, pool_size, meta_total = 0, meta_run;
    SnxU32 pc, dc, fc, slots;
    unsigned char *seen = NULL;
    unsigned char* colors = NULL;
    Region* regions = NULL;
    size_t nregions = 0;
    char why[256];
    *out = NULL;
    if (!n) {
        snx_error("out of memory reading %s", path);
        return -1;
    }
    n->path = snx_strdup(path);
    if (!n->path) {
        badf(n, "out of memory");
        goto fail;
    }
    n->file = snx_fopen(path, "rb");
    if (!n->file) {
        badf(n, "cannot read it: %s", snx_os_error(why, sizeof why));
        goto fail;
    }
    actual = snx_file_size(path);
    if (plat_pread(n->file, sb, sizeof sb, 0) != (int64_t)sizeof sb) {
        badf(n, "shorter than a NUP superblock");
        goto fail;
    }
    if (memcmp(sb, "NUP\x01", 4)) {
        badf(n, "not a NUP (no NUP\\x01 magic)");
        goto fail;
    }
    hsize = ld16(sb + 4);
    toc_off = ld64(sb + 8);
    n->toc_size = ld64(sb + 0x10);
    blob = ld64(sb + 0x38);
    fsize = ld64(sb + 0x40);
    pc = ld32(sb + 0x48);
    if (hsize < 0x80 || ld16(sb + 6) < 1 || toc_off != hsize || ld32(sb + 0x4C)) {
        badf(n, "unsupported NUP header (size %llu, version %u, flags %u)", (unsigned long long)hsize,
             (unsigned)ld16(sb + 6), (unsigned)ld32(sb + 0x4C));
        goto fail;
    }
    if (!pc) {
        badf(n, "no packages");
        goto fail;
    }
    if (fsize != actual) {
        badf(n, "%llu bytes, its header says %llu (copied or downloaded partly?)", (unsigned long long)actual,
             (unsigned long long)fsize);
        goto fail;
    }
    if (blob % 16 || blob < toc_off || n->toc_size > blob - toc_off || blob > fsize) {
        badf(n, "its TOC and data regions overlap or lie past the file");
        goto fail;
    }
    n->blob_offset = blob;
    n->file_size = fsize;
    /* the TOC's SHA-256 first: no value of it is trusted before it matches */
    if (n->toc_size > SIZE_MAX || !(n->toc = (unsigned char*)malloc((size_t)n->toc_size))) {
        badf(n, "out of memory for its table of contents (%llu bytes)", (unsigned long long)n->toc_size);
        goto fail;
    }
    if (plat_pread(n->file, n->toc, n->toc_size, toc_off) != (int64_t)n->toc_size) {
        badf(n, "cannot read its table of contents");
        goto fail;
    }
    if (!sha_ok(n->toc, n->toc_size, sb + 0x18)) {
        badf(n, "its table of contents does not match its SHA-256 (damaged file)");
        goto fail;
    }
    if (n->toc_size < 0x30) { /* the header below reads up to 0x28; the packages start at 0x30 */
        badf(n, "its table of contents is shorter than its header");
        goto fail;
    }
    if (ld32(n->toc) != 0x01434F54u || ld32(n->toc + 4) != pc) {
        badf(n, "malformed table of contents (magic or package count)");
        goto fail;
    }
    {
        SnxU64 dcount = ld64(n->toc + 8), fcount = ld64(n->toc + 0x10);
        if (dcount > NUP_NONE || fcount > NUP_NONE) {
            badf(n, "too many folders or files in its table of contents");
            goto fail;
        }
        dc = (SnxU32)dcount;
        fc = (SnxU32)fcount;
    }
    pool_off = ld64(n->toc + 0x18);
    pool_size = ld64(n->toc + 0x20);
    n->packages_off = 0x30;
    n->dirs_off = n->packages_off + (SnxU64)pc * 0x40;
    n->files_off = n->dirs_off + (SnxU64)dc * 0x18;
    n->children_off = n->files_off + (SnxU64)fc * 0x50;
    need = n->children_off;
    if (need > n->toc_size || pool_off < need || (pool_off - need) % 4 || pool_off > n->toc_size ||
        pool_size > n->toc_size - pool_off) {
        badf(n, "its table of contents' regions overlap or lie past it");
        goto fail;
    }
    if ((pool_off - need) / 4 > NUP_NONE) {
        badf(n, "too many child slots in its table of contents");
        goto fail;
    }
    slots = (SnxU32)((pool_off - need) / 4);
    n->child_count = slots;
    n->pool_off = pool_off;
    n->pool_size = pool_size;
    n->package_count = pc;
    n->dir_count = dc;
    n->file_count = fc;
    /* packages: kinds, flags, tree roots and meta bounds */
    {
        unsigned bases = 0, updates = 0, standalone = 0;
        for (SnxU32 i = 0; i < pc; i++) {
            const unsigned char* p = prec(n, i);
            unsigned kind = p[0x18], flags = p[0x19];
            SnxU64 mo = ld64(p + 0x20);
            SnxU32 ms = ld32(p + 0x28), root = ld32(p + 8), ex = ld32(p + 0xC), ro = ld32(p + 0x10);
            if (kind >= 5 || kind == 3 || kind == 4) {
                badf(n, "package %u of unsupported kind %u", i, kind);
                goto fail;
            }
            if (flags & ~1u || ld16(p + 0x1A) || ld32(p + 0x1C)) {
                badf(n, "package %u has reserved fields or flags set", i);
                goto fail;
            }
            if (root >= dc || (ex != NUP_NONE && ex >= dc) || (ro != NUP_NONE && ro >= dc)) {
                badf(n, "package %u's tree roots are out of bounds", i);
                goto fail;
            }
            if (ms) {
                if (mo > fsize || mo < toc_off + n->toc_size || ms > fsize - mo) {
                    badf(n, "package %u's meta block lies past the file or in its TOC", i);
                    goto fail;
                }
                if (meta_total > SIZE_MAX - ms) {
                    badf(n, "out of memory for its meta blocks");
                    goto fail;
                }
                meta_total += ms;
            }
            bases += kind == 0;
            if (kind == 1) {
                updates++;
                standalone += (flags & 1) != 0;
            }
        }
        if (bases > 1) {
            badf(n, "%u base packages: a NUP holds one base game", bases);
            goto fail;
        }
        if (!bases && updates && standalone != updates) {
            badf(n, "no base game, and its updates are not all marked standalone_update");
            goto fail;
        }
    }
    /* folders and files: names, child ranges, codecs and extents */
    {
        SnxU64 child_sum = 0;
        for (SnxU32 i = 0; i < dc; i++) {
            const unsigned char* d = drec(n, i);
            SnxU32 no = ld32(d), nl = ld32(d + 4), first = ld32(d + 8), count = ld32(d + 0xC);
            if (no > pool_size || nl > pool_size - no || !name_ok(name_ptr(n, no), nl, 0)) {
                badf(n, "folder %u's name is out of bounds or no label", i);
                goto fail;
            }
            if ((SnxU64)first + count > slots) {
                badf(n, "folder %u's children lie past the children array", i);
                goto fail;
            }
            child_sum += count;
        }
        if (child_sum != slots) {
            badf(n, "its folders' child counts do not fill the children array");
            goto fail;
        }
        for (SnxU32 i = 0; i < fc; i++) {
            const unsigned char* f = frec(n, i);
            SnxU32 no = ld32(f), nl = ld32(f + 4);
            SnxU64 size = ld64(f + 8), eo = ld64(f + 0x10), es = ld64(f + 0x18);
            unsigned codec = f[0x40], cflags = f[0x41];
            if (no > pool_size || nl > pool_size - no || !name_ok(name_ptr(n, no), nl, 1)) {
                badf(n, "file %u's name is out of bounds or no label", i);
                goto fail;
            }
            if (codec > 1 || cflags) {
                badf(n, "file %u uses codec %u (this reads raw and zstd)", i, codec);
                goto fail;
            }
            if (size > (SnxU64)INT64_MAX) {
                badf(n, "file %u is too large", i);
                goto fail;
            }
            if (!size) {
                if (eo || es || codec) {
                    badf(n, "empty file %u with data", i);
                    goto fail;
                }
            } else if (eo > fsize || eo < blob || eo % 16 || !es || es > fsize - eo || (codec == 0 && es != size)) {
                badf(n, "file %u's extent is out of bounds or unaligned", i);
                goto fail;
            }
        }
    }
    /* children: every node one parent, names sorted and unique within a folder */
    seen = (unsigned char*)calloc((SnxU64)dc + fc, 1);
    if (!seen) {
        badf(n, "out of memory validating its tree");
        goto fail;
    }
    for (SnxU32 i = 0; i < dc; i++) {
        const unsigned char* d = drec(n, i);
        SnxU32 first = ld32(d + 8), count = ld32(d + 0xC);
        const unsigned char* prev = NULL;
        SnxU32 prev_len = 0;
        for (SnxU32 s = first; s < first + count; s++) {
            SnxU32 id = child_id(n, s);
            const unsigned char* nm;
            SnxU32 nl;
            if (id >= dc + fc) {
                badf(n, "child %u of folder %u is out of bounds", id, i);
                goto fail;
            }
            if (seen[id]) {
                badf(n, "node %u has more than one parent (damaged file)", id);
                goto fail;
            }
            seen[id] = 1;
            if (id < dc) {
                nm = name_ptr(n, ld32(drec(n, id)));
                nl = ld32(drec(n, id) + 4);
            } else {
                nm = name_ptr(n, ld32(frec(n, id - dc)));
                nl = ld32(frec(n, id - dc) + 4);
            }
            if (prev && name_cmp(prev, prev_len, nm, nl) >= 0) {
                badf(n, "folder %u's children are not sorted by name, or a name repeats", i);
                goto fail;
            }
            prev = nm;
            prev_len = nl;
        }
    }
    /* no folder contains itself, at any depth (a walk of the tree would loop for ever) */
    colors = (unsigned char*)calloc(dc, 1);
    if (!colors) {
        badf(n, "out of memory validating its tree");
        goto fail;
    }
    {
        typedef struct {
            SnxU32 dir, pos;
        } DfsFrame;
        DfsFrame* stack = (DfsFrame*)malloc((SnxU64)dc * sizeof *stack);
        if (!stack) {
            badf(n, "out of memory validating its tree");
            goto fail;
        }
        for (SnxU32 top = 0; top < dc; top++) {
            size_t depth = 0;
            if (colors[top]) continue;
            colors[top] = 1;
            stack[depth++] = (DfsFrame){top, 0};
            while (depth) {
                SnxU32 dir = stack[depth - 1].dir, pos = stack[depth - 1].pos;
                const unsigned char* d = drec(n, dir);
                SnxU32 first = ld32(d + 8), count = ld32(d + 0xC);
                if (pos == count) {
                    colors[dir] = 2;
                    depth--;
                    continue;
                }
                stack[depth - 1].pos++;
                SnxU32 id = child_id(n, first + pos);
                if (id >= dc) continue; /* a file */
                if (colors[id] == 1) {
                    badf(n, "folder %u contains itself (damaged file)", id);
                    free(stack);
                    goto fail;
                }
                if (!colors[id]) {
                    if (depth >= NUP_DEPTH_MAX) {
                        badf(n, "its tree is deeper than %u folders", NUP_DEPTH_MAX);
                        free(stack);
                        goto fail;
                    }
                    colors[id] = 1;
                    stack[depth++] = (DfsFrame){id, 0};
                }
            }
        }
        free(stack);
    }
    /* extents and meta blocks: no overlap, but a dedup extent shared by files of the same content (SPEC 3.6) */
    regions = (Region*)malloc(((SnxU64)fc + pc) * sizeof *regions);
    if (!regions) {
        badf(n, "out of memory validating its extents");
        goto fail;
    }
    for (SnxU32 i = 0; i < fc; i++) {
        const unsigned char* f = frec(n, i);
        if (!ld64(f + 8)) continue;
        regions[nregions++] = (Region){ld64(f + 0x10), ld64(f + 0x18), i, 0};
    }
    for (SnxU32 i = 0; i < pc; i++) {
        const unsigned char* p = prec(n, i);
        SnxU32 ms = ld32(p + 0x28);
        if (ms) regions[nregions++] = (Region){ld64(p + 0x20), ms, i, 1};
    }
    qsort(regions, nregions, sizeof *regions, region_cmp);
    {
        SnxU64 end = 0;
        const Region* prev = NULL;
        for (size_t i = 0; i < nregions; i++) {
            const Region* r = &regions[i];
            if (r->off < end) {
                int dedup = prev && !r->meta && !prev->meta && r->off == prev->off && r->size == prev->size;
                if (dedup) {
                    const unsigned char* a = frec(n, r->idx);
                    const unsigned char* b = frec(n, prev->idx);
                    dedup = ld64(a + 8) == ld64(b + 8) && a[0x40] == b[0x40] && !memcmp(a + 0x20, b + 0x20, 32);
                }
                if (!dedup) {
                    badf(n, "its extents or meta blocks overlap (damaged file)");
                    goto fail;
                }
            }
            if (r->off + r->size > end) end = r->off + r->size;
            prev = r;
        }
    }
    /* the meta blocks read whole, their TLV walks bounded */
    n->meta_data = ((SnxU64)pc * sizeof(SnxU64) + 7) & ~(SnxU64)7;
    if (n->meta_data > SIZE_MAX - meta_total ||
        !(n->meta = (unsigned char*)malloc((size_t)(n->meta_data + meta_total)))) {
        badf(n, "out of memory for its meta blocks");
        goto fail;
    }
    meta_run = n->meta_data;
    for (SnxU32 i = 0; i < pc; i++) {
        const unsigned char* p = prec(n, i);
        SnxU64 mo = ld64(p + 0x20);
        SnxU32 ms = ld32(p + 0x28), left = ms;
        SnxU64 at = meta_run;
        ((SnxU64*)n->meta)[i] = ms ? at : ~(SnxU64)0;
        if (!ms) continue;
        if (plat_pread(n->file, n->meta + at, ms, mo) != (int64_t)ms) {
            badf(n, "cannot read package %u's meta block", i);
            goto fail;
        }
        while (left >= 8) {
            const unsigned char* t = n->meta + at;
            SnxU32 ts = ld32(t + 4);
            if (ts > left - 8) {
                badf(n, "package %u's meta record runs past its block", i);
                goto fail;
            }
            at += 8 + ts;
            left -= 8 + ts;
        }
        meta_run += ms;
    }
    /* the extent cache and the streaming cursor */
    n->cache = (NupExtent*)calloc(NUP_CACHE_SLOTS, sizeof *n->cache);
    n->stream.z = ZSTD_createDCtx();
    n->stream.sha = EVP_MD_CTX_new();
    if (!n->cache || !n->stream.z || !n->stream.sha) {
        badf(n, "out of memory for its read cache");
        goto fail;
    }
    free(seen);
    free(colors);
    free(regions);
    *out = n;
    return 0;
fail:
    free(seen);
    free(colors);
    free(regions);
    snx_nup_close(n);
    return -1;
}

/* ------------------------------------------------------------------ extent reads, through the cache */

static void stream_reset(NupStream* s, SnxU64 extent, SnxU64 size, SnxU64 in_end, int codec) {
    s->extent = extent;
    s->size = size;
    s->in_at = extent;
    s->in_end = in_end;
    s->out_at = 0;
    s->codec = codec;
    s->verified = s->bad = s->ended = 0;
    s->in_pos = s->in_size = 0;
    if (s->z) ZSTD_DCtx_reset(s->z, ZSTD_reset_session_only);
    if (s->sha) EVP_DigestInit_ex(s->sha, EVP_sha256(), NULL);
}

static int stream_finish(SnxNup* n, NupStream* s, const unsigned char* sha) {
    unsigned char dig[32];
    unsigned len = 0;
    if (!EVP_DigestFinal_ex(s->sha, dig, &len) || len != 32 || memcmp(dig, sha, 32)) {
        s->bad = 1;
        return badf(n, "a file's extent does not match its SHA-256 (damaged file)");
    }
    s->verified = 1;
    return 0;
}

/* up to cap bytes of the streamed zstd extent into out, hashed as they come: the bytes produced, 0 at the frame's end,
   -1 on a damaged or cut-short frame */
static int stream_chunk(SnxNup* n, NupStream* s, unsigned char* out, size_t cap) {
    ZSTD_outBuffer ob = {out, cap, 0};
    while (ob.pos < cap && !s->ended) {
        size_t before_out = ob.pos, before_in;
        size_t ret;
        if (s->in_pos == s->in_size) {
            SnxU64 want;
            if (s->in_at >= s->in_end) return -1; /* the frame needs more than the extent holds */
            want = s->in_end - s->in_at < NUP_IO ? s->in_end - s->in_at : NUP_IO;
            if (plat_pread(n->file, s->in, want, s->in_at) != (int64_t)want) return -1;
            s->in_at += want;
            s->in_size = (size_t)want;
            s->in_pos = 0;
        }
        before_in = s->in_pos;
        {
            ZSTD_inBuffer ib = {s->in, s->in_size, s->in_pos};
            ret = ZSTD_decompressStream(s->z, &ob, &ib);
            s->in_pos = ib.pos;
        }
        if (ZSTD_isError(ret)) return -1;
        if (ret == 0) {
            s->ended = 1;
            break;
        }
        if (ob.pos == before_out && s->in_pos == before_in && s->in_at >= s->in_end) return -1; /* nothing moved */
    }
    if (ob.pos && EVP_DigestUpdate(s->sha, out, ob.pos) != 1) return -1;
    s->out_at += ob.pos;
    return (int)ob.pos;
}

/* a raw extent too big to hold: checked whole once, then read where it lies */
static int raw_verify(SnxNup* n, NupStream* s, const unsigned char* sha) {
    SnxU64 at = s->extent;
    EVP_DigestInit_ex(s->sha, EVP_sha256(), NULL);
    while (at < s->in_end) {
        SnxU64 want = s->in_end - at < NUP_IO ? s->in_end - at : NUP_IO;
        if (plat_pread(n->file, s->in, want, at) != (int64_t)want) return -1;
        if (EVP_DigestUpdate(s->sha, s->in, (size_t)want) != 1) return -1;
        at += want;
    }
    s->out_at = s->size;
    return stream_finish(n, s, sha);
}

static int big_read(SnxNup* n, SnxU64 fsize, SnxU64 eoff, SnxU64 esize, unsigned codec, const unsigned char* sha,
                    SnxU64 rel, unsigned char* buf, size_t size) {
    NupStream* s = &n->stream;
    if (s->extent != eoff || s->size != fsize) stream_reset(s, eoff, fsize, eoff + esize, (int)codec);
    if (s->bad) return -1;
    if (codec == 0) {
        if (!s->verified && raw_verify(n, s, sha)) return -1;
        return plat_pread(n->file, buf, size, eoff + rel) == (int64_t)size ? 0 : -1;
    }
    if (rel < s->out_at) stream_reset(s, eoff, fsize, eoff + esize, (int)codec); /* a zstd extent reads from its start */
    {
        unsigned char scratch[NUP_IO];
        size_t got = 0;
        while (s->out_at < rel) {
            SnxU64 k = rel - s->out_at < NUP_IO ? rel - s->out_at : NUP_IO;
            int got_k = stream_chunk(n, s, scratch, (size_t)k);
            if (got_k <= 0) return -1;
        }
        while (got < size) {
            size_t cap = size - got < NUP_IO ? size - got : NUP_IO; /* stream_chunk's count is an int: keep it small */
            int got_k = stream_chunk(n, s, buf + got, cap);
            if (got_k <= 0) return -1;
            got += (size_t)got_k;
        }
    }
    if (s->out_at == fsize && !s->verified && stream_finish(n, s, sha)) return -1;
    if (s->ended && s->out_at != fsize) {
        s->bad = 1;
        return badf(n, "a file's extent decompresses to %llu bytes, its record says %llu",
                    (unsigned long long)s->out_at, (unsigned long long)fsize);
    }
    return s->bad ? -1 : 0;
}

static int extent_fill(SnxNup* n, NupExtent* e, SnxU64 fsize, SnxU64 eoff, SnxU64 esize, unsigned codec,
                       const unsigned char* sha) {
    unsigned char* data = (unsigned char*)malloc((size_t)fsize);
    int ok;
    if (!data) return -1;
    if (codec == 0) {
        ok = plat_pread(n->file, data, fsize, eoff) == (int64_t)fsize;
    } else {
        unsigned char* comp = (unsigned char*)malloc(esize ? (size_t)esize : 1);
        ok = comp && plat_pread(n->file, comp, esize, eoff) == (int64_t)esize;
        if (ok) {
            unsigned long long cs = ZSTD_getFrameContentSize(comp, (size_t)esize);
            ok = cs == fsize && ZSTD_decompress(data, (size_t)fsize, comp, (size_t)esize) == fsize;
        }
        free(comp);
    }
    if (ok) ok = sha_ok(data, fsize, sha);
    if (!ok) {
        free(data);
        e->bad = 1;
        return badf(n, "a file's extent does not match its SHA-256 or size (damaged file)");
    }
    e->data = data;
    e->size = fsize;
    e->used = ++n->cache_clock;
    n->cache_bytes += fsize;
    return 0;
}

/* the cache slot of an extent, made room for: an existing one (touched), or a free one after the least used are let
   go until the budget holds it. NULL when it cannot be held */
static NupExtent* cache_take(SnxNup* n, SnxU64 key, SnxU64 size) {
    for (size_t i = 0; i < NUP_CACHE_SLOTS; i++)
        if (n->cache[i].key == key) {
            n->cache[i].used = ++n->cache_clock;
            return &n->cache[i];
        }
    for (;;) {
        NupExtent* free_slot = NULL;
        NupExtent* lru = NULL;
        for (size_t i = 0; i < NUP_CACHE_SLOTS; i++) {
            NupExtent* e = &n->cache[i];
            if (!e->key) {
                if (!free_slot) free_slot = e;
            } else if (!lru || e->used < lru->used) {
                lru = e;
            }
        }
        if (free_slot && n->cache_bytes + size <= NUP_CACHE_BUDGET) {
            free_slot->key = key;
            free_slot->size = 0;
            free_slot->data = NULL;
            free_slot->bad = 0;
            free_slot->used = ++n->cache_clock;
            return free_slot;
        }
        if (!lru) return NULL;
        free(lru->data);
        n->cache_bytes -= lru->size;
        lru->key = 0;
        lru->data = NULL;
        lru->size = 0;
        lru->bad = 0;
    }
}

/* size bytes at rel of file fi's content: 0, or -1. The extent is held whole in the cache when it fits, else streamed */
static int extent_read(SnxNup* n, SnxU32 fi, SnxU64 rel, unsigned char* buf, size_t size) {
    const unsigned char* f = frec(n, fi);
    SnxU64 fsize = ld64(f + 8), eoff = ld64(f + 0x10), esize = ld64(f + 0x18);
    unsigned codec = f[0x40];
    if (rel > fsize || size > fsize - rel) return -1;
    if (!size) return 0;
    if (fsize <= NUP_CACHE_ENTRY_MAX) {
        NupExtent* e = cache_take(n, eoff, fsize);
        if (!e || e->bad) return -1;
        if (!e->data && extent_fill(n, e, fsize, eoff, esize, codec, f + 0x20)) return -1;
        memcpy(buf, e->data + rel, size);
        return 0;
    }
    return big_read(n, fsize, eoff, esize, codec, f + 0x20, rel, buf, size);
}

/* ------------------------------------------------------------------ the merged tree and the virtual RomFS */

typedef struct {
    SnxU32 name, name_len; /* into the build's name pool */
    SnxU32 first_child, child_count; /* a folder's children, a contiguous range of the build's kids array */
    SnxU32 file; /* the NUP file index, NUP_NONE for a folder */
    unsigned char is_dir;
} NupNode;

typedef struct {
    SnxNup* nup;
    NupNode* nodes;
    size_t node_count, node_room;
    SnxU32* kids; /* node indices, each folder's children a reserved range (a subtree's nodes interleave, its child
                     indices do not) */
    size_t kid_count, kid_room;
    char* names;
    size_t name_size, name_room;
} NupBuild;

static SnxU32 node_add(NupBuild* b, NupNode node) {
    if (b->node_count >= NUP_NONE) return NUP_NONE; /* the index is a SnxU32, NUP_NONE its sentinel */
    if (b->node_count == b->node_room) {
        size_t room = b->node_room ? b->node_room * 2 : 256;
        NupNode* grown = (NupNode*)snx_realloc(b->nodes, room * sizeof *grown);
        if (!grown) return NUP_NONE;
        b->nodes = grown;
        b->node_room = room;
    }
    b->nodes[b->node_count] = node;
    return (SnxU32)b->node_count++;
}

/* count child slots reserved for a folder, filled as its children are laid (their own subtrees reserve elsewhere) */
static SnxU32 kids_reserve(NupBuild* b, size_t count) {
    if (b->kid_count + count > NUP_NONE) return NUP_NONE;
    if (b->kid_count + count > b->kid_room) {
        size_t room = b->kid_room ? b->kid_room : 256;
        SnxU32* grown;
        while (room < b->kid_count + count) room *= 2;
        grown = (SnxU32*)snx_realloc(b->kids, room * sizeof *grown);
        if (!grown) return NUP_NONE;
        b->kids = grown;
        b->kid_room = room;
    }
    {
        SnxU32 at = (SnxU32)b->kid_count;
        b->kid_count += count;
        return at;
    }
}

static SnxU32 name_add(NupBuild* b, const unsigned char* p, SnxU32 len) {
    if (b->name_size + len + 1 > NUP_NONE) return NUP_NONE; /* the pool offset is a SnxU32 */
    if (b->name_size + len + 1 > b->name_room) {
        size_t room = b->name_room ? b->name_room : 4096;
        char* grown;
        while (room < b->name_size + len + 1) room *= 2;
        grown = (char*)snx_realloc(b->names, room);
        if (!grown) return NUP_NONE;
        b->names = grown;
        b->name_room = room;
    }
    {
        SnxU32 at = (SnxU32)b->name_size;
        memcpy(b->names + at, p, len);
        b->names[at + len] = 0;
        b->name_size += len + 1;
        return at;
    }
}

/* a folder's child: its name, kind and index, from a children slot */
typedef struct {
    const unsigned char* name;
    SnxU32 len, id;
    int is_dir;
} NupChild;

static NupChild child_of(const SnxNup* n, SnxU32 slot) {
    NupChild c;
    SnxU32 id = child_id(n, slot);
    const unsigned char* r;
    c.is_dir = id < n->dir_count;
    c.id = c.is_dir ? id : id - n->dir_count;
    r = c.is_dir ? drec(n, c.id) : frec(n, c.id);
    c.name = name_ptr(n, ld32(r));
    c.len = ld32(r + 4);
    return c;
}

/* the subtree of a folder or file laid into the build: a folder's child indices reserved as one range, its children's
   own subtrees laid beyond it */
static SnxU32 lay_node(NupBuild* b, int is_dir, SnxU32 id) {
    NupNode node = {0};
    const unsigned char* r = is_dir ? drec(b->nup, id) : frec(b->nup, id);
    SnxU32 at;
    node.name = name_add(b, name_ptr(b->nup, ld32(r)), ld32(r + 4));
    node.name_len = ld32(r + 4);
    if (node.name == NUP_NONE) return NUP_NONE;
    node.is_dir = (unsigned char)is_dir;
    node.file = is_dir ? NUP_NONE : id;
    at = node_add(b, node);
    if (at == NUP_NONE) return NUP_NONE;
    if (is_dir) {
        SnxU32 first = ld32(r + 8), count = ld32(r + 0xC), made = 0;
        node.first_child = kids_reserve(b, count);
        if (node.first_child == NUP_NONE) return NUP_NONE;
        for (SnxU32 s = first; s < first + count; s++) {
            NupChild c = child_of(b->nup, s);
            SnxU32 child;
            if (!c.is_dir && artifact(c.name, c.len)) continue;
            child = lay_node(b, c.is_dir, c.id);
            if (child == NUP_NONE) return NUP_NONE;
            b->kids[node.first_child + made++] = child;
        }
        node.child_count = made;
        b->nodes[at] = node;
    }
    return at;
}

/* the base's folder merged with the update's (either -1 for none): the update's file shadows the base's of its path,
   folders union, the base's other files survive. Both child lists are sorted by name (validated at open) */
static SnxU32 merge_dir(NupBuild* b, int base_dir, int upd_dir) {
    NupNode node = {0};
    SnxNup* n = b->nup;
    const unsigned char* br = base_dir >= 0 ? drec(n, (SnxU32)base_dir) : NULL;
    const unsigned char* ur = upd_dir >= 0 ? drec(n, (SnxU32)upd_dir) : NULL;
    const unsigned char* nr = ur ? ur : br;
    SnxU32 at, made = 0;
    SnxU32 bfirst = br ? ld32(br + 8) : 0, bcount = br ? ld32(br + 0xC) : 0;
    SnxU32 ufirst = ur ? ld32(ur + 8) : 0, ucount = ur ? ld32(ur + 0xC) : 0;
    SnxU32 bi = 0, ui = 0;
    node.name = name_add(b, name_ptr(n, ld32(nr)), ld32(nr + 4));
    node.name_len = ld32(nr + 4);
    if (node.name == NUP_NONE) return NUP_NONE;
    node.is_dir = 1;
    node.file = NUP_NONE;
    at = node_add(b, node);
    if (at == NUP_NONE) return NUP_NONE;
    node.first_child = kids_reserve(b, (size_t)bcount + ucount);
    if (node.first_child == NUP_NONE) return NUP_NONE;
    while (bi < bcount || ui < ucount) {
        NupChild bc, uc;
        int have_b = bi < bcount, have_u = ui < ucount;
        int cmp;
        SnxU32 child;
        if (have_b) {
            bc = child_of(n, bfirst + bi);
            if (!bc.is_dir && artifact(bc.name, bc.len)) {
                bi++;
                continue;
            }
        }
        if (have_u) {
            uc = child_of(n, ufirst + ui);
            if (!uc.is_dir && artifact(uc.name, uc.len)) {
                ui++;
                continue;
            }
        }
        cmp = have_b && have_u ? name_cmp(bc.name, bc.len, uc.name, uc.len) : have_b ? -1 : 1;
        if (cmp < 0) {
            child = lay_node(b, bc.is_dir, bc.id);
            bi++;
        } else if (cmp > 0) {
            child = lay_node(b, uc.is_dir, uc.id);
            ui++;
        } else {
            /* the update's wins, whatever its kind; two folders union */
            child = bc.is_dir && uc.is_dir ? merge_dir(b, (int)bc.id, (int)uc.id) : lay_node(b, uc.is_dir, uc.id);
            bi++;
            ui++;
        }
        if (child == NUP_NONE) return NUP_NONE;
        b->kids[node.first_child + made++] = child;
    }
    node.child_count = made;
    b->nodes[at] = node;
    return at;
}

/* the RomFS image's layout, as fs.c's romfs_build makes it (Switchbrew's "RomFS"): the hash seed and step are the
   format's, which the game's own tables were built with */
static SnxU32 rhash(SnxU32 parent, const char* name) {
    SnxU32 h = parent ^ 123456789u;
    for (const unsigned char* p = (const unsigned char*)name; *p; p++) h = ((h >> 5) | (h << 27)) ^ *p;
    return h;
}
static SnxU32 hcount(SnxU32 c) {
    if (c < 3) return 3;
    if (c < 19) return c | 1;
    while (c % 2 == 0 || c % 3 == 0 || c % 5 == 0 || c % 7 == 0 || c % 11 == 0 || c % 13 == 0 || c % 17 == 0) c++;
    return c;
}
static SnxU64 entry_size(SnxU32 fixed, SnxU32 len) { return fixed + (((SnxU64)len + 3) & ~(SnxU64)3); }

typedef struct {
    SnxU64 off, size; /* the file's data, relative to the image's data start */
    SnxU32 file;      /* the NUP file index */
} NupRFile;

typedef struct {
    SnxHacFs base;
    SnxNup* nup;
    char* names;
    SnxHacEntry* files; /* the ExeFS's files */
    struct {
        SnxU32 file;     /* the NUP file index, NUP_NONE for a meta TLV */
        SnxU64 meta_off; /* the TLV payload's offset in nup->meta */
        unsigned char from_meta;
    }* srcs;
    size_t count;
    unsigned char* meta; /* the synthesized RomFS tables */
    SnxU64 meta_size, data_off, romfs_size;
    NupRFile* rfiles; /* in data-offset order, as the file table is laid */
    size_t nrfiles;
} NupFs;

static void rscan(const NupNode* nodes, const SnxU32* kids, SnxU32 at, SnxU32* ndirs, SnxU32* nfiles, SnxU64* db,
                  SnxU64* fb) {
    const NupNode* d = &nodes[at];
    for (SnxU32 i = 0; i < d->child_count; i++) {
        SnxU32 ci = kids[d->first_child + i];
        const NupNode* c = &nodes[ci];
        if (c->is_dir) {
            ++*ndirs;
            *db += entry_size(0x18, c->name_len);
            rscan(nodes, kids, ci, ndirs, nfiles, db, fb);
        } else {
            ++*nfiles;
            *fb += entry_size(0x20, c->name_len);
        }
    }
}

/* the virtual image's tables synthesized from the merged tree under root: 0, or -1 (out of memory, or too large) */
static int romfs_synth(NupFs* fs, const NupNode* nodes, const SnxU32* kids, const char* names, SnxU32 root) {
    SnxU32 ndirs = 1, nfiles = 0, dbuckets, fbuckets, nd, nf, i;
    SnxU64 dir_bytes = 0x18, file_bytes = 0, dhash, dtab, fhash, ftab, end, data = 0;
    typedef struct {
        SnxU32 node, parent, off, child, file;
    } RDir;
    RDir* dirs;
    unsigned char* m;
    rscan(nodes, kids, root, &ndirs, &nfiles, &dir_bytes, &file_bytes);
    if (dir_bytes >= NUP_NONE || file_bytes >= NUP_NONE || ndirs > INT32_MAX || nfiles > INT32_MAX) return -1;
    dbuckets = hcount(ndirs);
    fbuckets = hcount(nfiles);
    dhash = 0x50;
    dtab = dhash + (SnxU64)dbuckets * 4;
    fhash = dtab + dir_bytes;
    ftab = fhash + (SnxU64)fbuckets * 4;
    end = ftab + file_bytes;
    if (end > SIZE_MAX || !(m = (unsigned char*)calloc(1, (size_t)end))) return -1;
    fs->meta = m;
    fs->meta_size = end;
    dirs = (RDir*)malloc((SnxU64)ndirs * sizeof *dirs);
    fs->rfiles = (NupRFile*)malloc((nfiles ? nfiles : 1) * sizeof *fs->rfiles);
    if (!dirs || !fs->rfiles) {
        free(dirs);
        return -1;
    }
    memset(m + dhash, 0xFF, (size_t)dbuckets * 4);
    memset(m + fhash, 0xFF, (size_t)fbuckets * 4);
    /* the folders, breadth first, with their table offsets */
    dirs[0] = (RDir){root, 0, 0, NUP_NONE, NUP_NONE};
    nd = 1;
    {
        SnxU32 off = 0x18;
        for (i = 0; i < nd; i++) {
            const NupNode* d = &nodes[dirs[i].node];
            for (SnxU32 k = 0; k < d->child_count; k++) {
                SnxU32 ci = kids[d->first_child + k];
                const NupNode* c = &nodes[ci];
                if (!c->is_dir) continue;
                if (dirs[i].child == NUP_NONE) dirs[i].child = off;
                dirs[nd] = (RDir){ci, i, off, NUP_NONE, NUP_NONE};
                nd++;
                off += (SnxU32)entry_size(0x18, c->name_len);
            }
        }
    }
    /* the files, folder by folder, with their data offsets (each at a multiple of 16) */
    nf = 0;
    {
        SnxU32 off = 0;
        for (i = 0; i < nd; i++) {
            const NupNode* d = &nodes[dirs[i].node];
            unsigned char* e = NULL;
            for (SnxU32 k = 0; k < d->child_count; k++) {
                const NupNode* c = &nodes[kids[d->first_child + k]];
                SnxU64 size;
                SnxU32 b;
                if (c->is_dir) continue;
                size = ld64(frec(fs->nup, c->file) + 8);
                if (e) snx_st_le32(e + 4, off);
                if (dirs[i].file == NUP_NONE) dirs[i].file = off;
                data = (data + 15) & ~(SnxU64)15;
                if (data > (SnxU64)INT64_MAX - size) {
                    free(dirs);
                    return -1;
                }
                e = m + ftab + off;
                snx_st_le32(e, dirs[i].off);
                snx_st_le32(e + 4, NUP_NONE);
                snx_st_le64(e + 8, data);
                snx_st_le64(e + 16, size);
                b = rhash(dirs[i].off, names + c->name) % fbuckets;
                memcpy(e + 24, m + fhash + (SnxU64)b * 4, 4);
                snx_st_le32(m + fhash + (SnxU64)b * 4, off);
                snx_st_le32(e + 28, c->name_len);
                memcpy(e + 0x20, names + c->name, c->name_len);
                fs->rfiles[nf] = (NupRFile){data, size, c->file};
                nf++;
                data += size;
                off += (SnxU32)entry_size(0x20, c->name_len);
            }
        }
    }
    /* the folder entries, now that their first files are known */
    for (i = 0; i < nd; i++) {
        unsigned char* e = m + dtab + dirs[i].off;
        const char* name = i ? names + nodes[dirs[i].node].name : "";
        SnxU32 len = i ? nodes[dirs[i].node].name_len : 0;
        SnxU32 parent = dirs[dirs[i].parent].off, b;
        int last = i + 1 == nd || dirs[i + 1].parent != dirs[i].parent || !i;
        snx_st_le32(e, parent);
        snx_st_le32(e + 4, last ? NUP_NONE : dirs[i + 1].off);
        snx_st_le32(e + 8, dirs[i].child);
        snx_st_le32(e + 12, dirs[i].file);
        b = rhash(parent, name) % dbuckets;
        memcpy(e + 16, m + dhash + (SnxU64)b * 4, 4);
        snx_st_le32(m + dhash + (SnxU64)b * 4, dirs[i].off);
        snx_st_le32(e + 20, len);
        memcpy(e + 0x18, name, len);
    }
    free(dirs);
    fs->nrfiles = nf;
    fs->data_off = (end + 0x1FF) & ~(SnxU64)0x1FF;
    if (data > (SnxU64)INT64_MAX - fs->data_off) return -1;
    fs->romfs_size = fs->data_off + data;
    snx_st_le64(m, 0x50);
    snx_st_le64(m + 8, dhash);
    snx_st_le64(m + 16, (SnxU64)dbuckets * 4);
    snx_st_le64(m + 24, dtab);
    snx_st_le64(m + 32, dir_bytes);
    snx_st_le64(m + 40, fhash);
    snx_st_le64(m + 48, (SnxU64)fbuckets * 4);
    snx_st_le64(m + 56, ftab);
    snx_st_le64(m + 64, file_bytes);
    snx_st_le64(m + 72, fs->data_off);
    return 0;
}

/* ------------------------------------------------------------------ the file system ops */

static void nup_fs_close(SnxHacFs* f) {
    NupFs* fs = (NupFs*)f;
    free(fs->names);
    free(fs->files);
    free(fs->srcs);
    free(fs->meta);
    free(fs->rfiles);
    free(fs);
}

static size_t nup_fs_files(SnxHacFs* f, const SnxHacEntry** files) {
    NupFs* fs = (NupFs*)f;
    *files = fs->files;
    return fs->count;
}

static int nup_fs_read(SnxHacFs* f, size_t file, SnxU64 offset, void* buffer, size_t size) {
    NupFs* fs = (NupFs*)f;
    const SnxHacEntry* e = &fs->files[file];
    if (offset > e->size || size > e->size - offset) return -1;
    if (fs->srcs[file].from_meta) {
        memcpy(buffer, fs->nup->meta + fs->srcs[file].meta_off + offset, size);
        return 0;
    }
    return extent_read(fs->nup, fs->srcs[file].file, offset, (unsigned char*)buffer, size);
}

static SnxU64 nup_fs_romfs_size(const SnxHacFs* f) { return ((const NupFs*)f)->romfs_size; }

static int nup_fs_read_romfs(SnxHacFs* f, SnxU64 offset, void* buffer, size_t size) {
    NupFs* fs = (NupFs*)f;
    unsigned char* out = (unsigned char*)buffer;
    if (offset > fs->romfs_size || size > fs->romfs_size - offset) return -1;
    while (size) {
        SnxU64 n;
        if (offset < fs->meta_size) { /* the synthesized tables */
            n = fs->meta_size - offset < size ? fs->meta_size - offset : size;
            memcpy(out, fs->meta + offset, (size_t)n);
        } else if (offset < fs->data_off) { /* the tables padded to where the data starts: zeros */
            n = fs->data_off - offset < size ? fs->data_off - offset : size;
            memset(out, 0, (size_t)n);
        } else {
            SnxU64 rel = offset - fs->data_off;
            size_t lo = 0, hi = fs->nrfiles;
            long k;
            while (lo < hi) { /* the last file starting at or before rel */
                size_t mid = lo + (hi - lo) / 2;
                if (fs->rfiles[mid].off <= rel) lo = mid + 1;
                else hi = mid;
            }
            k = (long)lo - 1;
            if (k >= 0 && rel - fs->rfiles[k].off < fs->rfiles[k].size) {
                const NupRFile* rf = &fs->rfiles[k];
                n = rf->off + rf->size - rel < size ? rf->off + rf->size - rel : size;
                if (extent_read(fs->nup, rf->file, rel - rf->off, out, (size_t)n)) return -1;
            } else { /* an alignment gap, or the image's end: zeros */
                SnxU64 next = fs->romfs_size - fs->data_off;
                if (lo < fs->nrfiles) next = fs->rfiles[lo].off;
                n = next - rel < size ? next - rel : size;
                memset(out, 0, (size_t)n);
            }
        }
        out += n;
        offset += n;
        size -= (size_t)n;
    }
    return 0;
}

static const SnxHacFsOps nup_fs_ops = {nup_fs_close, nup_fs_files, nup_fs_read, nup_fs_romfs_size, nup_fs_read_romfs};

/* the ExeFS's direct file children merged (the update's shadow the base's per name), into the build's name pool and
   the fs's entry arrays: 0, or -1 */
static int exefs_merge(NupFs* fs, NupBuild* b, int base_dir, int upd_dir) {
    SnxNup* n = b->nup;
    SnxU32 bfirst = 0, bcount = 0, ufirst = 0, ucount = 0, bi = 0, ui = 0;
    size_t count = 0, room = 0;
    const unsigned char* br = base_dir >= 0 ? drec(n, (SnxU32)base_dir) : NULL;
    const unsigned char* ur = upd_dir >= 0 ? drec(n, (SnxU32)upd_dir) : NULL;
    if (br) {
        bfirst = ld32(br + 8);
        bcount = ld32(br + 0xC);
    }
    if (ur) {
        ufirst = ld32(ur + 8);
        ucount = ld32(ur + 0xC);
    }
    while (bi < bcount || ui < ucount) {
        NupChild bc, uc;
        int have_b = bi < bcount, have_u = ui < ucount, cmp, take_u;
        if (have_b) {
            bc = child_of(n, bfirst + bi);
            if (bc.is_dir || artifact(bc.name, bc.len)) {
                bi++;
                continue;
            }
        }
        if (have_u) {
            uc = child_of(n, ufirst + ui);
            if (uc.is_dir || artifact(uc.name, uc.len)) {
                ui++;
                continue;
            }
        }
        cmp = have_b && have_u ? name_cmp(bc.name, bc.len, uc.name, uc.len) : have_b ? -1 : 1;
        take_u = cmp >= 0;
        {
            NupChild c = take_u ? uc : bc;
            SnxU32 name = name_add(b, c.name, c.len);
            SnxU64 size = ld64(frec(n, c.id) + 8);
            if (name == NUP_NONE) return -1;
            if (count == room) {
                size_t grow = room ? room * 2 : 16;
                SnxHacEntry* fe = (SnxHacEntry*)snx_realloc(fs->files, grow * sizeof *fe);
                void* se;
                if (!fe) return -1;
                fs->files = fe; /* kept before the next realloc, so a failure of it leaks nothing */
                se = snx_realloc(fs->srcs, grow * sizeof *fs->srcs);
                if (!se) return -1;
                fs->srcs = se;
                room = grow;
            }
            /* the name's offset kept until the pool stops growing (snx_nup_fs turns it into the pointer) */
            fs->files[count] = (SnxHacEntry){NULL, name, size};
            fs->srcs[count].file = c.id;
            fs->srcs[count].from_meta = 0;
            count++;
        }
        if (cmp < 0) bi++;
        else if (cmp > 0) ui++;
        else {
            bi++;
            ui++;
        }
    }
    fs->count = count;
    return 0;
}

SnxHacFs* snx_nup_fs(SnxNup* n, size_t pkg, int base_pkg) {
    NupFs* fs = (NupFs*)calloc(1, sizeof *fs);
    NupBuild b = {0};
    SnxU32 root = NUP_NONE;
    int base_romfs = -1, upd_romfs, base_exefs = -1, upd_exefs;
    if (!fs) {
        snx_error("out of memory reading a NUP package");
        return NULL;
    }
    fs->base.ops = &nup_fs_ops;
    fs->nup = n;
    b.nup = n;
    upd_romfs = pkg_dir(n, pkg, 0x10) == NUP_NONE ? -1 : (int)pkg_dir(n, pkg, 0x10);
    upd_exefs = pkg_dir(n, pkg, 0x0C) == NUP_NONE ? -1 : (int)pkg_dir(n, pkg, 0x0C);
    if (base_pkg >= 0) {
        base_romfs = pkg_dir(n, (size_t)base_pkg, 0x10) == NUP_NONE ? -1 : (int)pkg_dir(n, (size_t)base_pkg, 0x10);
        base_exefs = pkg_dir(n, (size_t)base_pkg, 0x0C) == NUP_NONE ? -1 : (int)pkg_dir(n, (size_t)base_pkg, 0x0C);
    }
    if (exefs_merge(fs, &b, base_exefs, upd_exefs)) goto fail;
    /* main.npdm from the meta TLV when the tree lacks it (SPEC 5: the producer writes it when the ExeFS has one) */
    {
        size_t i;
        SnxU64 off;
        SnxU32 size;
        int have = 0, mp = (int)pkg;
        for (i = 0; i < fs->count; i++)
            if (!strcmp(b.names + fs->files[i].offset, "main.npdm")) have = 1;
        if (!have && !meta_find(n, pkg, 1, &off, &size) && base_pkg >= 0 && meta_find(n, (size_t)base_pkg, 1, &off, &size))
            mp = base_pkg;
        if (!have && meta_find(n, (size_t)mp, 1, &off, &size)) {
            SnxU32 name = name_add(&b, (const unsigned char*)"main.npdm", 9);
            SnxHacEntry* fe;
            void* se;
            if (name == NUP_NONE) goto fail;
            fe = (SnxHacEntry*)snx_realloc(fs->files, (fs->count + 1) * sizeof *fe);
            if (!fe) goto fail;
            fs->files = fe;
            se = snx_realloc(fs->srcs, (fs->count + 1) * sizeof *fs->srcs);
            if (!se) goto fail;
            fs->srcs = se;
            fs->files[fs->count] = (SnxHacEntry){NULL, name, size};
            fs->srcs[fs->count].file = NUP_NONE;
            fs->srcs[fs->count].meta_off = off;
            fs->srcs[fs->count].from_meta = 1;
            fs->count++;
        }
    }
    if (base_romfs >= 0 || upd_romfs >= 0) {
        root = merge_dir(&b, base_romfs, upd_romfs);
        if (root == NUP_NONE) goto fail;
        if (romfs_synth(fs, b.nodes, b.kids, b.names, root)) goto fail;
    }
    free(b.nodes); /* the synth copied the tables and the file extents' order out; the merged tree is spent */
    free(b.kids);
    fs->names = b.names;
    /* the pool has stopped growing: the ExeFS names' offsets become the pointers the entries keep */
    for (size_t i = 0; i < fs->count; i++) {
        fs->files[i].name = fs->names + fs->files[i].offset;
        fs->files[i].offset = 0;
    }
    return &fs->base;
fail:
    free(b.nodes);
    free(b.kids);
    free(b.names);
    snx_error("%s: a NUP package's trees cannot be laid out (out of memory, or too large)", n->path);
    nup_fs_close(&fs->base);
    return NULL;
}
