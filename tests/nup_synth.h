/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* A synthetic NUP container (the NUP format's SPEC.md v1) built in memory for the reader's tests: a superblock, a
   table of contents (packages, a folder tree, files, children, a string pool) whose SHA-256 is written, and a blob of
   raw or zstd extents, deduped by content. Nothing from a console. The includer defines CHECK(value) first */
#ifndef SNX_TEST_NUP_SYNTH_H
#define SNX_TEST_NUP_SYNTH_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <zstd.h>

typedef struct {
    unsigned char* data;
    size_t size;
} nup_blob_t;

static inline void* nup_zalloc(size_t size) {
    void* p = calloc(1, size ? size : 1);
    CHECK(p != NULL);
    return p;
}
static inline size_t nup_align(size_t v, size_t a) { return (v + a - 1) / a * a; }
static inline void nup_put32(unsigned char* p, uint32_t v) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(v >> (8 * i));
}
static inline void nup_put64(unsigned char* p, uint64_t v) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8 * i));
}
static inline void nup_sha(const unsigned char* data, size_t size, unsigned char out[32]) {
    unsigned len = 0;
    CHECK(EVP_Digest(data, size, out, &len, EVP_sha256(), NULL) && len == 32);
}
static inline nup_blob_t nup_text(const char* text) {
    nup_blob_t b = {nup_zalloc(strlen(text)), strlen(text)};
    memcpy(b.data, text, b.size);
    return b;
}

/* one file of a package, by its path under the root ("exefs/main", "romfs/sub/a.bin"): codec 0 raw, 1 zstd; no_size
   compresses without the frame's content size (a damaged frame the reader must refuse) */
typedef struct {
    const char* path;
    nup_blob_t content;
    int codec, no_size;
} NupEntry;

typedef struct {
    uint64_t title_id;
    uint32_t version;
    uint8_t kind, flags; /* kind 0 base, 1 update, 2 addon; flags bit0 standalone_update */
    const NupEntry* entries;
    unsigned count;
    nup_blob_t meta; /* a TLV block, or {NULL, 0} */
} NupPkg;

typedef struct {
    char* name;
    int is_dir, parent, file;
    int* kids;
    unsigned nkids, room;
    uint32_t dir_idx, file_idx, name_off, name_len;
} NupNode;

typedef struct {
    int node;
    nup_blob_t content; /* uncompressed, borrowed */
    int codec, no_size;
    unsigned char sha[32];
    uint64_t size, eoff, esize;
    nup_blob_t stored; /* the bytes written to the blob, owned */
    uint32_t file_idx;
} NupFile;

typedef struct {
    NupNode* nodes;
    unsigned nnodes, nroom;
    NupFile* files;
    unsigned nfiles, froom;
    unsigned char* pool;
    uint32_t pool_size, pool_room;
} NupSynth;

static inline int nup_node(NupSynth* s, const char* name, int is_dir, int parent) {
    NupNode n = {0};
    if (s->nnodes == s->nroom) {
        s->nroom = s->nroom ? s->nroom * 2 : 64;
        s->nodes = realloc(s->nodes, s->nroom * sizeof *s->nodes);
        CHECK(s->nodes != NULL);
    }
    n.name = strdup(name);
    CHECK(n.name != NULL);
    n.is_dir = is_dir;
    n.parent = parent;
    n.file = -1;
    s->nodes[s->nnodes] = n;
    if (parent >= 0) {
        NupNode* p = &s->nodes[parent];
        if (p->nkids == p->room) {
            p->room = p->room ? p->room * 2 : 8;
            p->kids = realloc(p->kids, p->room * sizeof *p->kids);
            CHECK(p->kids != NULL);
        }
        p->kids[p->nkids++] = (int)s->nnodes;
    }
    return (int)s->nnodes++;
}
static inline int nup_find(NupSynth* s, int dir, const char* name) {
    for (unsigned i = 0; i < s->nodes[dir].nkids; i++)
        if (!strcmp(s->nodes[s->nodes[dir].kids[i]].name, name)) return s->nodes[dir].kids[i];
    return -1;
}
/* a file's path laid into the tree under root, its folders made where they are none */
static inline void nup_add(NupSynth* s, int root, const NupEntry* e) {
    char* copy = strdup(e->path);
    char* part = copy;
    int dir = root;
    CHECK(copy != NULL);
    for (;;) {
        char* slash = strchr(part, '/');
        if (!slash) break;
        *slash = 0;
        int next = nup_find(s, dir, part);
        if (next < 0) next = nup_node(s, part, 1, dir);
        CHECK(s->nodes[next].is_dir);
        dir = next;
        part = slash + 1;
    }
    CHECK(nup_find(s, dir, part) < 0); /* a path given twice would make two children of one name */
    int node = nup_node(s, part, 0, dir);
    free(copy);
    if (s->nfiles == s->froom) {
        s->froom = s->froom ? s->froom * 2 : 64;
        s->files = realloc(s->files, s->froom * sizeof *s->files);
        CHECK(s->files != NULL);
    }
    NupFile f = {0};
    f.node = node;
    f.content = e->content;
    f.codec = e->content.size ? e->codec : 0;
    f.no_size = e->no_size;
    f.size = e->content.size;
    s->files[s->nfiles] = f;
    s->nodes[node].file = (int)s->nfiles++;
}
static inline uint32_t nup_intern(NupSynth* s, const char* name) {
    uint32_t len = (uint32_t)strlen(name);
    for (uint32_t at = 0; at < s->pool_size;) { /* the pool's entries are NUL-separated */
        uint32_t elen = (uint32_t)strlen((char*)s->pool + at);
        if (elen == len && !memcmp(s->pool + at, name, len)) return at;
        at += elen + 1;
    }
    if (s->pool_size + len + 1 > s->pool_room) {
        s->pool_room = s->pool_room ? s->pool_room : 256;
        while (s->pool_room < s->pool_size + len + 1) s->pool_room *= 2;
        s->pool = realloc(s->pool, s->pool_room);
        CHECK(s->pool != NULL);
    }
    uint32_t at = s->pool_size;
    memcpy(s->pool + at, name, len);
    s->pool[at + len] = 0;
    s->pool_size += len + 1;
    return at;
}
/* a folder's children sorted by name (bytewise), as the format lays them: an insertion sort, the test trees are small */
static inline void nup_sort_kids(NupNode* nodes, NupNode* dir) {
    for (unsigned i = 1; i < dir->nkids; i++) {
        int key = dir->kids[i];
        unsigned j = i;
        while (j && strcmp(nodes[dir->kids[j - 1]].name, nodes[key].name) > 0) {
            dir->kids[j] = dir->kids[j - 1];
            j--;
        }
        dir->kids[j] = key;
    }
}

static inline nup_blob_t nup_zstd_frame(nup_blob_t in, int no_size) {
    ZSTD_CCtx* c = ZSTD_createCCtx();
    CHECK(c != NULL);
    if (no_size) CHECK(!ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_contentSizeFlag, 0)));
    size_t cap = ZSTD_compressBound(in.size);
    nup_blob_t out = {nup_zalloc(cap ? cap : 1), 0};
    out.size = ZSTD_compress2(c, out.data, cap, in.data, in.size);
    CHECK(!ZSTD_isError(out.size));
    ZSTD_freeCCtx(c);
    return out;
}

/* the whole .nup of pkgs, in memory: the caller writes it to a file and frees it */
static inline nup_blob_t nup_build(const NupPkg* pkgs, unsigned npkg) {
    NupSynth s = {0};
    int* roots = nup_zalloc(npkg * sizeof *roots);
    unsigned ndirs = 0, nfiles = 0, nslots = 0;
    CHECK(npkg >= 1);
    for (unsigned p = 0; p < npkg; p++) {
        roots[p] = nup_node(&s, "", 1, -1);
        for (unsigned i = 0; i < pkgs[p].count; i++) nup_add(&s, roots[p], &pkgs[p].entries[i]);
    }
    /* index the folders and files, and sort each folder's children by name */
    for (unsigned i = 0; i < s.nnodes; i++) {
        if (s.nodes[i].is_dir) s.nodes[i].dir_idx = ndirs++;
        else s.nodes[i].file_idx = nfiles++;
    }
    for (unsigned i = 0; i < s.nnodes; i++)
        if (s.nodes[i].is_dir && s.nodes[i].nkids > 1) nup_sort_kids(s.nodes, &s.nodes[i]);
    for (unsigned i = 0; i < s.nnodes; i++)
        if (s.nodes[i].is_dir) nslots += s.nodes[i].nkids;
    /* the string pool, and each node's name in it */
    for (unsigned i = 0; i < s.nnodes; i++) {
        s.nodes[i].name_off = nup_intern(&s, s.nodes[i].name);
        s.nodes[i].name_len = (uint32_t)strlen(s.nodes[i].name);
    }
    uint64_t pool_off = 0x30 + (uint64_t)npkg * 0x40 + (uint64_t)ndirs * 0x18 + (uint64_t)nfiles * 0x50 +
                        (uint64_t)nslots * 4;
    uint64_t toc_size = pool_off + s.pool_size;
    uint64_t blob = nup_align(0x80 + toc_size, 16);
    /* the extents, deduped by content (SPEC 3.6), laid 16-aligned from the blob's start */
    uint64_t cursor = blob;
    NupFile** by_idx = nup_zalloc((nfiles ? nfiles : 1) * sizeof *by_idx);
    for (unsigned i = 0; i < s.nfiles; i++) {
        s.files[i].file_idx = s.nodes[s.files[i].node].file_idx;
        by_idx[s.files[i].file_idx] = &s.files[i];
    }
    for (unsigned i = 0; i < nfiles; i++) {
        NupFile* f = by_idx[i];
        f->file_idx = i;
        if (!f->size) {
            f->eoff = f->esize = 0;
            f->codec = 0;
            memset(f->sha, 0, 32);
            nup_sha((const unsigned char*)"", 0, f->sha);
            continue;
        }
        nup_sha(f->content.data, f->content.size, f->sha);
        f->stored = f->codec == 1 ? nup_zstd_frame(f->content, f->no_size)
                                  : (nup_blob_t){memcpy(nup_zalloc(f->content.size), f->content.data, f->content.size),
                                                 f->content.size};
        int dup = 0;
        for (unsigned j = 0; j < i; j++) {
            NupFile* g = by_idx[j];
            if (g->size == f->size && g->codec == f->codec && !memcmp(g->sha, f->sha, 32)) {
                f->eoff = g->eoff;
                f->esize = g->esize;
                free(f->stored.data);
                f->stored = (nup_blob_t){NULL, 0};
                dup = 1;
                break;
            }
        }
        if (!dup) {
            f->eoff = cursor;
            f->esize = f->stored.size;
            cursor = nup_align(cursor + f->stored.size, 16);
        }
    }
    /* the meta blocks after the extents */
    uint64_t* meta_off = nup_zalloc(npkg * sizeof *meta_off);
    for (unsigned p = 0; p < npkg; p++) {
        meta_off[p] = pkgs[p].meta.size ? cursor : 0;
        cursor += pkgs[p].meta.size;
    }
    uint64_t file_size = cursor;
    nup_blob_t out = {nup_zalloc(file_size), file_size};
    unsigned char* d = out.data;
    /* superblock */
    memcpy(d, "NUP\x01", 4);
    nup_put32(d + 4, 0x80); /* header_size u16, header_version u16 */
    d[6] = 1;
    nup_put64(d + 8, 0x80);
    nup_put64(d + 0x10, toc_size);
    nup_put64(d + 0x38, blob);
    nup_put64(d + 0x40, file_size);
    nup_put32(d + 0x48, npkg);
    /* TOC */
    unsigned char* t = d + 0x80;
    nup_put32(t, 0x01434F54u);
    nup_put32(t + 4, npkg);
    nup_put64(t + 8, ndirs);
    nup_put64(t + 0x10, nfiles);
    nup_put64(t + 0x18, pool_off);
    nup_put64(t + 0x20, s.pool_size);
    uint64_t at = 0x30;
    for (unsigned p = 0; p < npkg; p++) {
        unsigned char* r = t + at + (uint64_t)p * 0x40;
        int ex = nup_find(&s, roots[p], "exefs"), ro = nup_find(&s, roots[p], "romfs");
        nup_put64(r, pkgs[p].title_id);
        nup_put32(r + 8, s.nodes[roots[p]].dir_idx);
        nup_put32(r + 0xC, ex >= 0 ? s.nodes[ex].dir_idx : 0xFFFFFFFFu);
        nup_put32(r + 0x10, ro >= 0 ? s.nodes[ro].dir_idx : 0xFFFFFFFFu);
        nup_put32(r + 0x14, pkgs[p].version);
        r[0x18] = pkgs[p].kind;
        r[0x19] = pkgs[p].flags;
        nup_put64(r + 0x20, meta_off[p]);
        nup_put32(r + 0x28, (uint32_t)pkgs[p].meta.size);
    }
    at += (uint64_t)npkg * 0x40;
    /* folders in dir_idx order, with their child ranges */
    NupNode** dir_by_idx = nup_zalloc((ndirs ? ndirs : 1) * sizeof *dir_by_idx);
    for (unsigned i = 0; i < s.nnodes; i++)
        if (s.nodes[i].is_dir) dir_by_idx[s.nodes[i].dir_idx] = &s.nodes[i];
    uint32_t slot = 0;
    for (unsigned i = 0; i < ndirs; i++) {
        NupNode* n = dir_by_idx[i];
        unsigned char* r = t + at + (uint64_t)i * 0x18;
        nup_put32(r, n->name_off);
        nup_put32(r + 4, n->name_len);
        nup_put32(r + 8, slot);
        nup_put32(r + 0xC, n->nkids);
        for (unsigned k = 0; k < n->nkids; k++) {
            NupNode* c = &s.nodes[n->kids[k]];
            nup_put32(t + pool_off - (uint64_t)nslots * 4 + (uint64_t)slot * 4,
                      c->is_dir ? c->dir_idx : ndirs + c->file_idx);
            slot++;
        }
    }
    at += (uint64_t)ndirs * 0x18;
    for (unsigned i = 0; i < nfiles; i++) {
        NupFile* f = by_idx[i];
        NupNode* n = &s.nodes[f->node];
        unsigned char* r = t + at + (uint64_t)i * 0x50;
        nup_put32(r, n->name_off);
        nup_put32(r + 4, n->name_len);
        nup_put64(r + 8, f->size);
        nup_put64(r + 0x10, f->eoff);
        nup_put64(r + 0x18, f->esize);
        memcpy(r + 0x20, f->sha, 32);
        r[0x40] = (unsigned char)f->codec;
    }
    memcpy(t + pool_off, s.pool, s.pool_size);
    /* the blob's extents and the meta blocks */
    for (unsigned i = 0; i < nfiles; i++)
        if (by_idx[i]->stored.size) memcpy(d + by_idx[i]->eoff, by_idx[i]->stored.data, by_idx[i]->stored.size);
    for (unsigned p = 0; p < npkg; p++)
        if (pkgs[p].meta.size) memcpy(d + meta_off[p], pkgs[p].meta.data, pkgs[p].meta.size);
    nup_sha(t, toc_size, d + 0x18); /* the TOC's SHA-256, last */
    for (unsigned i = 0; i < s.nnodes; i++) {
        free(s.nodes[i].name);
        free(s.nodes[i].kids);
    }
    for (unsigned i = 0; i < s.nfiles; i++) free(s.files[i].stored.data);
    free(s.nodes);
    free(s.files);
    free(s.pool);
    free(roots);
    free(by_idx);
    free(dir_by_idx);
    free(meta_off);
    return out;
}

/* a TLV block built by appending records (SPEC 5): the caller frees it */
static inline void nup_tlv(nup_blob_t* block, uint16_t type, const void* payload, uint32_t size) {
    block->data = realloc(block->data, block->size + 8 + size);
    CHECK(block->data != NULL);
    unsigned char* r = block->data + block->size;
    nup_put32(r, type); /* type u16, reserved u16 zero */
    nup_put32(r + 4, size);
    memcpy(r + 8, payload, size);
    block->size += 8 + size;
}

#endif
