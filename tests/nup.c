/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* The native NUP reader (src/nx/runtime/driver/nup.c) on synthetic containers (tests/nup_synth.h): raw, zstd and
   zero-length files round-tripped through the virtual RomFS image and the ExeFS, nested folders, deduped extents, an
   update over its base and a DLC, a standalone update refused, and a matrix of damaged containers the reader must
   reject. Nothing from a console */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/utilities/common.h"
#include "nx/runtime/driver/container.h"
#include "nx/runtime/driver/nup.h"

static struct {
    unsigned checks;
    char said[2048];
    char* scratch;
    unsigned serial;
} g_nup;

static void check(int good, const char* expression, int line) {
    g_nup.checks++;
    if (!good) {
        fprintf(stderr, "nup.c:%d: check failed: %s\n", line, expression);
        exit(90);
    }
}
#define CHECK(value) check((value) != 0, #value, __LINE__)

#include "nup_synth.h"

static void said_line(const char* line) { snprintf(g_nup.said, sizeof g_nup.said, "%s", line); }

#define BASE_TITLE 0x0100000000001000ull
#define UPD_TITLE 0x0100000000001800ull
#define DLC_TITLE 0x0100000000002001ull

/* a compressible payload, so a zstd extent is smaller than its content */
static nup_blob_t pattern(size_t size) {
    nup_blob_t b = {nup_zalloc(size), size};
    for (size_t i = 0; i < size; i++) b.data[i] = (unsigned char)("nup synthetic payload "[i % 22]);
    return b;
}
static nup_blob_t npdm_blob(void) {
    nup_blob_t b = {nup_zalloc(0x80), 0x80};
    memcpy(b.data, "META", 4);
    return b;
}

/* a synthetic container written to a file of the scratch folder, its path owned */
static char* write_nup(nup_blob_t blob) {
    char* path = snx_format("%s/nup_%u.nup", g_nup.scratch, g_nup.serial++);
    CHECK(path != NULL);
    CHECK(!snx_write_file(path, blob.data, blob.size));
    free(blob.data);
    return path;
}
static SnxNup* open_nup(const char* path) {
    SnxNup* n = NULL;
    CHECK(snx_nup_open(&n, path) == 0);
    CHECK(n != NULL);
    return n;
}
/* a file of the virtual RomFS, by its path, compared with what it must hold */
static void romfs_is(SnxHacFs* fs, const char* name, const void* content, size_t size) {
    size_t got = 0;
    unsigned char* data = snx_romfs_file(fs, name, &got);
    CHECK(data != NULL);
    CHECK(got == size);
    CHECK(!memcmp(data, content, size));
    free(data);
}
static int count_each(void* context, const char* name, SnxU64 offset, SnxU64 size) {
    (void)name;
    (void)offset;
    (void)size;
    (*(unsigned*)context)++;
    return 0;
}
/* the ExeFS's file of a name, read whole and compared */
static void exefs_is(SnxHacFs* fs, const char* name, const void* content, size_t size) {
    const SnxHacEntry* files;
    size_t count = snx_hac_fs_files(fs, &files), i;
    unsigned char* data;
    for (i = 0; i < count && strcmp(files[i].name, name); i++) {}
    CHECK(i < count);
    CHECK(files[i].size == size);
    data = nup_zalloc(size ? size : 1);
    CHECK(snx_hac_fs_read(fs, i, 0, data, size) == 0);
    CHECK(!memcmp(data, content, size));
    free(data);
}

/* ------------------------------------------------------------------ round-trip, nested folders, dedup */

static void case_roundtrip(void) {
    nup_blob_t z = pattern(8192), nested = nup_text("nested content"), main = nup_text("MAINCODE");
    nup_blob_t npdm = npdm_blob();
    NupEntry entries[] = {
        {"exefs/main", main, 0, 0},        {"exefs/main.npdm", npdm, 0, 0},
        {"romfs/hello.bin", nup_text("hello"), 0, 0}, {"romfs/z.bin", z, 1, 0},
        {"romfs/empty.bin", {NULL, 0}, 0, 0},          {"romfs/sub/deep/nested.bin", nested, 0, 0},
    };
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 6, {NULL, 0}};
    char* path = write_nup(nup_build(&pkg, 1));
    SnxNup* n = open_nup(path);
    CHECK(snx_nup_count(n) == 1);
    CHECK(snx_nup_kind(n, 0) == 0);
    CHECK(snx_nup_title(n, 0) == BASE_TITLE);
    CHECK(snx_nup_version(n, 0) == 0x10000);
    CHECK(snx_nup_find(n, 0, BASE_TITLE) == 0);
    CHECK(snx_nup_find(n, 1, 0) == -1);
    SnxHacFs* fs = snx_nup_fs(n, 0, -1);
    CHECK(fs != NULL);
    CHECK(snx_hac_fs_romfs_size(fs) > 0);
    romfs_is(fs, "hello.bin", "hello", 5);
    romfs_is(fs, "z.bin", z.data, z.size);
    romfs_is(fs, "sub/deep/nested.bin", nested.data, nested.size);
    {
        size_t got = 1;
        unsigned char* data = snx_romfs_file(fs, "empty.bin", &got);
        CHECK(data != NULL && got == 0);
        free(data);
    }
    CHECK(snx_romfs_file(fs, "nope.bin", &(size_t){0}) == NULL);
    exefs_is(fs, "main", main.data, main.size);
    exefs_is(fs, "main.npdm", npdm.data, npdm.size);
    {
        unsigned count = 0;
        CHECK(snx_romfs_each(fs, ".bin", count_each, &count) == 0);
        CHECK(count == 4); /* hello, z, empty, nested */
    }
    snx_hac_fs_free(fs);
    snx_nup_close(n);
    remove(path);
    free(path);
    free(z.data);
    free(nested.data);
    free(main.data);
    free(npdm.data);
    free(entries[2].content.data);
}

static void case_dedup(void) {
    nup_blob_t shared = pattern(4096);
    NupEntry entries[] = {
        {"romfs/a.bin", shared, 1, 0},
        {"romfs/b.bin", shared, 1, 0}, /* the same content: one extent shared (SPEC 3.6) */
        {"romfs/c.bin", shared, 0, 0}, /* the same content raw: its own extent (a different codec) */
    };
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 3, {NULL, 0}};
    nup_blob_t blob = nup_build(&pkg, 1);
    char* path = write_nup(blob);
    SnxNup* n = open_nup(path); /* identical dedup extents are allowed */
    SnxHacFs* fs = snx_nup_fs(n, 0, -1);
    CHECK(fs != NULL);
    romfs_is(fs, "a.bin", shared.data, shared.size);
    romfs_is(fs, "b.bin", shared.data, shared.size);
    romfs_is(fs, "c.bin", shared.data, shared.size);
    snx_hac_fs_free(fs);
    snx_nup_close(n);
    remove(path);
    free(path);
    free(shared.data);
}

/* ------------------------------------------------------------------ update over base, and a DLC */

static void case_overlay(void) {
    nup_blob_t ba = nup_text("base-a"), bo = nup_text("base-only"), bc = nup_text("base-c");
    nup_blob_t ua = nup_text("upd-a"), uc = nup_text("upd-c"), un = nup_text("upd-new");
    nup_blob_t bm = nup_text("base-main"), um = nup_text("upd-main"), dlc = nup_text("dlc-data");
    nup_blob_t npdm = npdm_blob();
    NupEntry base[] = {
        {"exefs/main", bm, 0, 0}, {"exefs/main.npdm", npdm, 0, 0},
        {"romfs/a.bin", ba, 0, 0}, {"romfs/only-base.bin", bo, 0, 0}, {"romfs/sub/c.bin", bc, 0, 0},
    };
    NupEntry upd[] = {
        {"exefs/main", um, 0, 0}, {"exefs/main.npdm", npdm, 0, 0},
        {"romfs/a.bin", ua, 0, 0}, {"romfs/sub/c.bin", uc, 0, 0}, {"romfs/new.bin", un, 0, 0},
    };
    NupEntry addon[] = {{"romfs/dlc.bin", dlc, 0, 0}};
    NupPkg pkgs[] = {
        {BASE_TITLE, 0x10000, 0, 0, base, 5, {NULL, 0}},
        {UPD_TITLE, 0x20000, 1, 0, upd, 5, {NULL, 0}},
        {DLC_TITLE, 0, 2, 0, addon, 1, {NULL, 0}},
    };
    char* path = write_nup(nup_build(pkgs, 3));
    SnxNup* n = open_nup(path);
    CHECK(snx_nup_count(n) == 3);
    CHECK(snx_nup_newest_update(n) == 1);
    CHECK(snx_nup_find(n, 2, DLC_TITLE) == 2);
    CHECK(snx_nup_find(n, 2, 0) == 2);
    /* the update over the base: its files shadow, the base's others survive */
    SnxHacFs* merged = snx_nup_fs(n, 1, 0);
    CHECK(merged != NULL);
    romfs_is(merged, "a.bin", ua.data, ua.size);
    romfs_is(merged, "only-base.bin", bo.data, bo.size);
    romfs_is(merged, "sub/c.bin", uc.data, uc.size);
    romfs_is(merged, "new.bin", un.data, un.size);
    exefs_is(merged, "main", um.data, um.size);
    snx_hac_fs_free(merged);
    /* the base alone */
    SnxHacFs* base_fs = snx_nup_fs(n, 0, -1);
    romfs_is(base_fs, "a.bin", ba.data, ba.size);
    romfs_is(base_fs, "sub/c.bin", bc.data, bc.size);
    CHECK(snx_romfs_file(base_fs, "new.bin", &(size_t){0}) == NULL);
    exefs_is(base_fs, "main", bm.data, bm.size);
    snx_hac_fs_free(base_fs);
    /* the DLC, independent */
    SnxHacFs* aoc = snx_nup_fs(n, 2, -1);
    romfs_is(aoc, "dlc.bin", dlc.data, dlc.size);
    snx_hac_fs_free(aoc);
    /* through the container layer: the game's dump picks the base and the newest update */
    {
        SnxDump dump;
        CHECK(snx_dump_open(&dump, path, NULL, 0, NULL, NULL, g_nup.scratch, 0) == 0);
        CHECK(dump.nup != NULL);
        CHECK(dump.program.found && dump.program.title_id == BASE_TITLE);
        CHECK(dump.patch.found && dump.patch.title_id == UPD_TITLE);
        CHECK(snx_nca_keys(&dump, &dump.program, "x") == 0);
        SnxHacFs* fs = snx_dump_fs(&dump);
        CHECK(fs != NULL);
        romfs_is(fs, "a.bin", ua.data, ua.size); /* the merged image, as the runtime reads it */
        snx_hac_fs_free(fs);
        CHECK(snx_dump_html_fs(&dump) == NULL);
        snx_dump_close(&dump);
    }
    /* the DLC's dump opened alone (base NULL), its add-on picked by title ID */
    {
        SnxDump dump;
        CHECK(snx_dump_open(&dump, NULL, path, 0, NULL, NULL, g_nup.scratch, 0) == 0);
        SnxHacFs* fs = snx_dump_aoc_fs(&dump, DLC_TITLE);
        CHECK(fs != NULL);
        CHECK(dump.aoc.found && dump.aoc.title_id == DLC_TITLE);
        romfs_is(fs, "dlc.bin", dlc.data, dlc.size);
        snx_hac_fs_free(fs);
        snx_dump_close(&dump);
    }
    snx_nup_close(n);
    remove(path);
    free(path);
    free(ba.data); free(bo.data); free(bc.data); free(ua.data); free(uc.data); free(un.data);
    free(bm.data); free(um.data); free(dlc.data); free(npdm.data);
}

/* the NACP and icon a package's meta holds, through the container layer */
static void case_meta(void) {
    nup_blob_t nacp = {nup_zalloc(0x4000), 0x4000};
    nup_blob_t icon = nup_text("\xff\xd8\xff synthetic icon");
    nup_blob_t meta = {NULL, 0};
    strcpy((char*)nacp.data, "Synthetic NUP Game");
    nup_tlv(&meta, 0x0002, nacp.data, (uint32_t)nacp.size);
    nup_tlv(&meta, 0x0003, icon.data, (uint32_t)icon.size);
    nup_tlv(&meta, 0x0005, "Synthetic NUP Game", 18);
    NupEntry entries[] = {{"exefs/main", nup_text("M"), 0, 0}, {"romfs/a.bin", nup_text("a"), 0, 0}};
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 2, meta};
    char* path = write_nup(nup_build(&pkg, 1));
    SnxNup* n = open_nup(path);
    size_t size = 0;
    unsigned char* got = snx_nup_meta(n, 0, 0x0002, &size);
    CHECK(got != NULL && size == nacp.size && !memcmp(got, nacp.data, size));
    free(got);
    CHECK(snx_nup_meta(n, 0, 0x0099, &size) == NULL); /* an unknown type: none */
    snx_nup_close(n);
    {
        SnxDump dump;
        const char* why = NULL;
        CHECK(snx_dump_title(&dump, path, NULL, NULL, g_nup.scratch, 0, &(SnxU64){0}, &(SnxU64){0}, NULL) == 0);
        CHECK(dump.program.title_id == BASE_TITLE);
        unsigned char* nacp_got = snx_dump_nacp(&dump, &size, &why);
        CHECK(nacp_got != NULL && size == nacp.size);
        free(nacp_got);
        unsigned char* icon_got = snx_dump_icon(&dump, &size, &why);
        CHECK(icon_got != NULL && size == icon.size && !memcmp(icon_got, icon.data, size));
        free(icon_got);
        snx_dump_close(&dump);
    }
    remove(path);
    free(path);
    free(nacp.data); free(icon.data); free(meta.data);
    free(entries[0].content.data); free(entries[1].content.data);
}

/* ------------------------------------------------------------------ standalone update */

static void case_standalone(void) {
    NupEntry entries[] = {{"exefs/main", nup_text("M"), 0, 0}, {"romfs/a.bin", nup_text("a"), 0, 0}};
    /* an update marked standalone, no base: a valid NUP, but no game to read on its own */
    NupPkg pkg = {UPD_TITLE, 0x20000, 1, 1, entries, 2, {NULL, 0}};
    char* path = write_nup(nup_build(&pkg, 1));
    SnxNup* n = open_nup(path);
    CHECK(snx_nup_find(n, 0, 0) == -1);
    CHECK(snx_nup_newest_update(n) == 0);
    snx_nup_close(n);
    {
        SnxDump dump;
        snx_error_sink(said_line);
        CHECK(snx_dump_open(&dump, path, NULL, 0, NULL, NULL, g_nup.scratch, 0) != 0);
        CHECK(strstr(g_nup.said, "base") != NULL);
        snx_dump_close(&dump);
        snx_error_sink(NULL);
    }
    remove(path);
    free(path);
    free(entries[0].content.data); free(entries[1].content.data);
    /* no base, and the update not marked standalone: the container itself is refused */
    NupPkg bad = {UPD_TITLE, 0x20000, 1, 0, entries, 2, {NULL, 0}};
    char* badpath = write_nup(nup_build(&bad, 1));
    SnxNup* nn = NULL;
    snx_error_sink(said_line);
    CHECK(snx_nup_open(&nn, badpath) != 0);
    CHECK(nn == NULL);
    snx_error_sink(NULL);
    remove(badpath);
    free(badpath);
}

/* ------------------------------------------------------------------ the large-file data path and the cache */

/* a compressible payload distinct per seed, so dedup keeps each file's extent separate */
static nup_blob_t big_pattern(size_t size, unsigned seed) {
    nup_blob_t b = {nup_zalloc(size), size};
    for (size_t i = 0; i < size; i++) b.data[i] = (unsigned char)((i * 31 + seed) % 251);
    return b;
}

/* a large RomFS file read whole through read_romfs (the guest's path), not snx_romfs_file whose host helper caps a
   file at 16 MiB: the file table gives its data offset, the virtual image's read serves it through the extent cache */
typedef struct {
    const char* name;
    SnxU64 off, size;
    int found;
} BigFind;
static int big_find(void* context, const char* name, SnxU64 offset, SnxU64 size) {
    BigFind* f = (BigFind*)context;
    if (!strcmp(name, f->name)) {
        f->off = offset;
        f->size = size;
        f->found = 1;
        return 1; /* stop the walk */
    }
    return 0;
}
static void romfs_big_is(SnxHacFs* fs, const char* name, const void* content, size_t size) {
    BigFind f = {name, 0, 0, 0};
    unsigned char* data;
    snx_romfs_each(fs, "", big_find, &f);
    CHECK(f.found);
    CHECK(f.size == size);
    data = nup_zalloc(size ? size : 1);
    CHECK(snx_hac_fs_read_romfs(fs, f.off, data, size) == 0);
    CHECK(!memcmp(data, content, size));
    free(data);
}

/* an extent past NUP_CACHE_ENTRY_MAX (64 MiB) is streamed, not held whole: raw verified whole first, zstd decompressed
   in NUP_IO chunks, each round-tripped through the virtual RomFS (the path a real game's large files take) */
static void case_big_streams(void) {
    size_t big = 65ull << 20;
    nup_blob_t raw = pattern(big), z = pattern(big);
    NupEntry entries[] = {{"romfs/raw.bin", raw, 0, 0}, {"romfs/z.bin", z, 1, 0}};
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 2, {NULL, 0}};
    char* path = write_nup(nup_build(&pkg, 1));
    SnxNup* n = open_nup(path);
    SnxHacFs* fs = snx_nup_fs(n, 0, -1);
    CHECK(fs != NULL);
    romfs_big_is(fs, "raw.bin", raw.data, raw.size);
    romfs_big_is(fs, "z.bin", z.data, z.size);
    romfs_big_is(fs, "z.bin", z.data, z.size); /* streamed again: a big extent is never cached whole */
    snx_hac_fs_free(fs);
    snx_nup_close(n);
    remove(path);
    free(path);
    free(raw.data);
    free(z.data);
}

/* five 56 MiB extents (each under the 64 MiB cache entry cap) fill past the 256 MiB budget: the LRU evicts, and an
   evicted extent read again decompresses anew, still matching its SHA-256 */
static void case_cache_eviction(void) {
    enum { N = 5 };
    size_t each = 56ull << 20;
    NupEntry entries[N];
    nup_blob_t content[N];
    char names[N][16];
    for (unsigned i = 0; i < N; i++) {
        content[i] = big_pattern(each, i + 1);
        snprintf(names[i], sizeof names[i], "romfs/f%u.bin", i);
        entries[i] = (NupEntry){names[i], content[i], 1, 0};
    }
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, N, {NULL, 0}};
    char* path = write_nup(nup_build(&pkg, 1));
    SnxNup* n = open_nup(path);
    SnxHacFs* fs = snx_nup_fs(n, 0, -1);
    CHECK(fs != NULL);
    for (unsigned i = 0; i < N; i++) { /* 5 * 56 MiB > the 256 MiB budget: the first evicted by the last */
        char name[16];
        snprintf(name, sizeof name, "f%u.bin", i);
        romfs_big_is(fs, name, content[i].data, content[i].size);
    }
    romfs_big_is(fs, "f0.bin", content[0].data, content[0].size); /* evicted: decompressed again, verified again */
    romfs_big_is(fs, "f4.bin", content[4].data, content[4].size);
    snx_hac_fs_free(fs);
    snx_nup_close(n);
    remove(path);
    free(path);
    for (unsigned i = 0; i < N; i++) free(content[i].data);
}

/* main.npdm synthesized from the meta TLV when the ExeFS tree lacks it (SPEC 5): the package's own meta, then the
   base's when an update has none */
static void case_meta_npdm(void) {
    nup_blob_t npdm = npdm_blob();
    nup_blob_t meta = {NULL, 0};
    nup_tlv(&meta, 0x0001, npdm.data, (uint32_t)npdm.size);
    NupEntry entries[] = {{"exefs/main", nup_text("M"), 0, 0}, {"romfs/a.bin", nup_text("a"), 0, 0}};
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 2, meta};
    char* path = write_nup(nup_build(&pkg, 1));
    SnxNup* n = open_nup(path);
    SnxHacFs* fs = snx_nup_fs(n, 0, -1);
    CHECK(fs != NULL);
    exefs_is(fs, "main.npdm", npdm.data, npdm.size); /* not in the tree: served from the meta TLV */
    exefs_is(fs, "main", "M", 1);
    snx_hac_fs_free(fs);
    snx_nup_close(n);
    remove(path);
    free(path);
    free(meta.data);
    free(entries[0].content.data);
    free(entries[1].content.data);
    /* an update whose tree and meta lack main.npdm: the base's meta TLV supplies it */
    nup_blob_t base_meta = {NULL, 0};
    nup_tlv(&base_meta, 0x0001, npdm.data, (uint32_t)npdm.size);
    NupEntry base_entries[] = {{"exefs/main", nup_text("B"), 0, 0}};
    NupEntry upd_entries[] = {{"exefs/main", nup_text("U"), 0, 0}};
    NupPkg pkgs[2] = {
        {BASE_TITLE, 0x10000, 0, 0, base_entries, 1, base_meta},
        {UPD_TITLE, 0x20000, 1, 0, upd_entries, 1, {NULL, 0}},
    };
    char* upath = write_nup(nup_build(pkgs, 2));
    SnxNup* un = open_nup(upath);
    SnxHacFs* ufs = snx_nup_fs(un, 1, 0);
    CHECK(ufs != NULL);
    exefs_is(ufs, "main.npdm", npdm.data, npdm.size); /* from the base's meta */
    exefs_is(ufs, "main", "U", 1);                   /* the update's own main shadows the base's */
    snx_hac_fs_free(ufs);
    snx_nup_close(un);
    remove(upath);
    free(upath);
    free(base_meta.data);
    free(base_entries[0].content.data);
    free(upd_entries[0].content.data);
    free(npdm.data);
}

/* ------------------------------------------------------------------ the corruption matrix */

static uint32_t get32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get64(const unsigned char* p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }

/* the layout of a built container, to find a record to damage */
typedef struct {
    unsigned char* d;
    uint64_t toc_size, blob, file_size, pool_off, pool_size;
    uint32_t npkg, ndirs, nfiles, nslots;
    uint64_t pkg_off, dir_off, file_off, child_off;
} Layout;
static Layout layout_of(nup_blob_t b) {
    Layout l;
    l.d = b.data;
    l.toc_size = get64(b.data + 0x10);
    l.blob = get64(b.data + 0x38);
    l.file_size = get64(b.data + 0x40);
    l.npkg = get32(b.data + 0x48);
    unsigned char* t = b.data + 0x80;
    l.ndirs = (uint32_t)get64(t + 8);
    l.nfiles = (uint32_t)get64(t + 0x10);
    l.pool_off = get64(t + 0x18);
    l.pool_size = get64(t + 0x20);
    l.pkg_off = 0x80 + 0x30;
    l.dir_off = l.pkg_off + (uint64_t)l.npkg * 0x40;
    l.file_off = l.dir_off + (uint64_t)l.ndirs * 0x18;
    l.child_off = l.file_off + (uint64_t)l.nfiles * 0x50;
    l.nslots = (uint32_t)((l.pool_off - (l.child_off - 0x80)) / 4);
    return l;
}
/* the TOC's SHA-256 written again, so a damaged record is trusted up to the check it must fail */
static void reseal(nup_blob_t b) { nup_sha(b.data + 0x80, get64(b.data + 0x10), b.data + 0x18); }

static nup_blob_t valid_blob(void) {
    NupEntry entries[] = {
        {"exefs/main", nup_text("MAIN"), 0, 0},
        {"romfs/a.bin", nup_text("aaa"), 0, 0},
        {"romfs/b.bin", nup_text("bbb"), 0, 0},
        {"romfs/sub/c.bin", nup_text("ccc"), 0, 0},
    };
    NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 4, {NULL, 0}};
    nup_blob_t b = nup_build(&pkg, 1);
    free(entries[0].content.data); free(entries[1].content.data);
    free(entries[2].content.data); free(entries[3].content.data);
    return b;
}
/* a damaged container must not open: the blob written, snx_nup_open refused, nothing left */
static void refuses(nup_blob_t b, const char* what) {
    char* path = write_nup(b);
    SnxNup* n = NULL;
    snx_error_sink(said_line);
    int rc = snx_nup_open(&n, path);
    snx_error_sink(NULL);
    check(rc != 0 && n == NULL, what, __LINE__);
    CHECK(g_nup.said[0] != 0);
    remove(path);
    free(path);
}

static void case_corruption(void) {
    /* a flipped TOC byte: the SHA-256 fails before any record is trusted */
    {
        nup_blob_t b = valid_blob();
        b.data[0x80 + 0x30] ^= 0xFF;
        refuses(b, "toc byte flip");
    }
    /* a copy cut short */
    {
        nup_blob_t b = valid_blob();
        b.size -= 64;
        refuses(b, "truncation");
    }
    /* an extent past the file's end */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        nup_put64(l.d + l.file_off + 0x10, l.file_size); /* the first file's extent_offset */
        reseal(b);
        refuses(b, "extent past EOF");
    }
    /* two different files' extents overlapping */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        uint64_t e0 = get64(l.d + l.file_off + 0x10);
        nup_put64(l.d + l.file_off + 0x50 + 0x10, e0); /* the second file onto the first's extent */
        reseal(b);
        refuses(b, "extent overlap");
    }
    /* an unknown codec */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        l.d[l.file_off + 0x40] = 2;
        reseal(b);
        refuses(b, "bad codec");
    }
    /* a reserved package kind */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        l.d[l.pkg_off + 0x18] = 3;
        reseal(b);
        refuses(b, "bad kind");
    }
    /* an unknown superblock flag (not hashed) */
    {
        nup_blob_t b = valid_blob();
        nup_put32(b.data + 0x4C, 1);
        refuses(b, "superblock flags");
    }
    /* a package flag past bit0 */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        l.d[l.pkg_off + 0x19] = 2;
        reseal(b);
        refuses(b, "package flags");
    }
    /* a folder that contains itself */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        nup_put32(l.d + l.child_off, 0); /* the root's first child is the root itself */
        reseal(b);
        refuses(b, "cycle");
    }
    /* children out of order */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        /* the romfs folder's children a.bin, b.bin, sub: swap the first two slots */
        uint32_t romfs_dir = get32(l.d + l.pkg_off + 0x10);
        uint32_t first = get32(l.d + l.dir_off + (uint64_t)romfs_dir * 0x18 + 8);
        uint32_t s0 = get32(l.d + l.child_off + (uint64_t)first * 4);
        uint32_t s1 = get32(l.d + l.child_off + (uint64_t)(first + 1) * 4);
        nup_put32(l.d + l.child_off + (uint64_t)first * 4, s1);
        nup_put32(l.d + l.child_off + (uint64_t)(first + 1) * 4, s0);
        reseal(b);
        refuses(b, "unsorted children");
    }
    /* a node with two parents */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        uint32_t s0 = get32(l.d + l.child_off);
        nup_put32(l.d + l.child_off + 4, s0); /* the root's second child repeats the first */
        reseal(b);
        refuses(b, "duplicate child");
    }
    /* a name that is a path, not a label */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        unsigned char* pool = l.d + 0x80 + l.pool_off;
        unsigned char* found = NULL;
        for (uint64_t i = 0; i + 5 <= l.pool_size; i++)
            if (!memcmp(pool + i, "a.bin", 5)) {
                found = pool + i;
                break;
            }
        CHECK(found != NULL);
        found[1] = '/'; /* "a/bin" */
        reseal(b);
        refuses(b, "slash in name");
    }
    /* a name past the pool's end */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        nup_put32(l.d + l.file_off, (uint32_t)l.pool_size); /* the first file's name_off */
        reseal(b);
        refuses(b, "pool overrun");
    }
    /* a child id past every node */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        nup_put32(l.d + l.child_off, l.ndirs + l.nfiles);
        reseal(b);
        refuses(b, "bad child id");
    }
    /* a meta TLV that runs past its block */
    {
        unsigned char bad_meta[12] = {0};
        nup_put32(bad_meta, 0x0002);
        nup_put32(bad_meta + 4, 100); /* a payload of 100 bytes, but the block holds 4 */
        NupEntry entries[] = {{"romfs/a.bin", nup_text("a"), 0, 0}};
        NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 1, {bad_meta, sizeof bad_meta}};
        nup_blob_t b = nup_build(&pkg, 1);
        free(entries[0].content.data);
        refuses(b, "TLV truncation");
    }
    /* an extent whose bytes do not match its SHA-256: opens, but the read fails */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        uint64_t e0 = get64(l.d + l.file_off + 0x10);
        b.data[e0] ^= 0xFF; /* the first file's content (exefs/main), outside the TOC */
        char* path = write_nup(b);
        SnxNup* n = open_nup(path);
        SnxHacFs* fs = snx_nup_fs(n, 0, -1);
        CHECK(fs != NULL);
        const SnxHacEntry* files;
        size_t count = snx_hac_fs_files(fs, &files), i;
        for (i = 0; i < count && strcmp(files[i].name, "main"); i++) {}
        CHECK(i < count);
        unsigned char buf[8];
        snx_error_sink(said_line);
        CHECK(snx_hac_fs_read(fs, i, 0, buf, files[i].size) != 0);
        snx_error_sink(NULL);
        snx_hac_fs_free(fs);
        snx_nup_close(n);
        remove(path);
        free(path);
    }
    /* a zstd frame without its content size: opens, but the read fails */
    {
        NupEntry entries[] = {{"romfs/z.bin", pattern(4096), 1, 1}};
        NupPkg pkg = {BASE_TITLE, 0x10000, 0, 0, entries, 1, {NULL, 0}};
        char* path = write_nup(nup_build(&pkg, 1));
        SnxNup* n = open_nup(path);
        SnxHacFs* fs = snx_nup_fs(n, 0, -1);
        CHECK(fs != NULL);
        snx_error_sink(said_line);
        CHECK(snx_romfs_file(fs, "z.bin", &(size_t){0}) == NULL);
        snx_error_sink(NULL);
        snx_hac_fs_free(fs);
        snx_nup_close(n);
        remove(path);
        free(path);
        free(entries[0].content.data);
    }
    /* a TOC shorter than its header: the SHA matches, but the header's fields cannot be read (SPEC 6.1 bounds) */
    {
        nup_blob_t b = valid_blob();
        nup_put64(b.data + 0x10, 0x28); /* toc_size below the 0x30 header */
        reseal(b);
        refuses(b, "short TOC header");
    }
    /* an extent offset past EOF, its size making fsize - eo underflow rather than bound it */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        nup_put64(l.d + l.file_off + 0x10, l.file_size + 16);
        reseal(b);
        refuses(b, "extent offset underflow");
    }
    /* a meta block past EOF, its size making fsize - mo underflow rather than bound it */
    {
        nup_blob_t b = valid_blob();
        Layout l = layout_of(b);
        nup_put64(l.d + l.pkg_off + 0x20, l.file_size + 16);
        nup_put32(l.d + l.pkg_off + 0x28, 8);
        reseal(b);
        refuses(b, "meta offset underflow");
    }
}

int main(void) {
    g_nup.scratch = snx_temp_dir(NULL);
    CHECK(g_nup.scratch != NULL);
    case_roundtrip();
    case_dedup();
    case_overlay();
    case_meta();
    case_standalone();
    case_big_streams();
    case_cache_eviction();
    case_meta_npdm();
    case_corruption();
    snx_remove_tree(g_nup.scratch);
    free(g_nup.scratch);
    printf("nup: %u checks passed\n", g_nup.checks);
    return 0;
}
