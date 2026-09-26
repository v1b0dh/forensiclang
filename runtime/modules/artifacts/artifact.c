/*
 * JOCKY Runtime — Artifact implementation
 * runtime/modules/artifacts/artifact.c
 *
 * Cross-platform implementation of the artifact storage API.
 * Artifacts are stored as MessagePack-inspired binary blobs under
 * the directory set by JOCKY_ARTIFACT_DIR (default: ./jocky_artifacts/).
 *
 * FORMAT (per artifact file):
 *   Magic:   "JKYA" (4 bytes)
 *   Version: uint16_t little-endian
 *   Name:    uint8_t len + UTF-8 bytes
 *   Records: uint32_t count + repeated records
 *     Record:
 *       type:      uint8_t  (0 = memory_region, 1 = packet, 2 = process)
 *       base_addr: uint64_t (memory regions only)
 *       protect:   uint32_t (memory regions only)
 *       data_len:  uint32_t
 *       data:      bytes
 */

#include "artifact.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#   include <windows.h>
#   include <direct.h>
#   define MKDIR(p) _mkdir(p)
#else
#   include <sys/stat.h>
#   define MKDIR(p) mkdir((p), 0700)
#endif

/* ── Internal record ──────────────────────────────────────────────── */
#define RECORD_MEMORY  0
#define RECORD_PACKET  1
#define RECORD_PROCESS 2

typedef struct record_s {
    uint8_t    type;
    uint64_t   base_addr;
    uint32_t   protect;
    uint32_t   data_len;
    uint8_t   *data;
    struct record_s *next;
} record_t;

struct artifact_s {
    char      name[256];
    record_t *head;
    record_t *tail;
    uint32_t  count;
};

/* ── Helpers ─────────────────────────────────────────────────────── */
static const char *artifact_dir(void) {
    const char *env = getenv("JOCKY_ARTIFACT_DIR");
    return env ? env : "./jocky_artifacts";
}

static void ensure_dir(const char *path) {
    MKDIR(path);   /* ignore error if already exists */
}

static void write_u8(FILE *f, uint8_t v)  { fwrite(&v, 1, 1, f); }
static void write_u16(FILE *f, uint16_t v) { fwrite(&v, 2, 1, f); }
static void write_u32(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }
static void write_u64(FILE *f, uint64_t v) { fwrite(&v, 8, 1, f); }

/* ── Public API ──────────────────────────────────────────────────── */
artifact_t *artifact_create(const char *name) {
    artifact_t *a = (artifact_t *)calloc(1, sizeof(artifact_t));
    if (!a) return NULL;
    strncpy(a->name, name ? name : "unnamed", sizeof(a->name) - 1);
    return a;
}

void artifact_append_region(artifact_t *a,
                             uint64_t    base_addr,
                             const uint8_t *data,
                             size_t      size,
                             uint32_t    protect) {
    if (!a || !data || size == 0) return;
    record_t *r = (record_t *)calloc(1, sizeof(record_t));
    r->type      = RECORD_MEMORY;
    r->base_addr = base_addr;
    r->protect   = protect;
    r->data_len  = (uint32_t)size;
    r->data      = (uint8_t *)malloc(size);
    if (!r->data) { free(r); return; }
    memcpy(r->data, data, size);

    if (a->tail) a->tail->next = r;
    else         a->head = r;
    a->tail = r;
    a->count++;
}

void artifact_append_packet(artifact_t *a,
                             const void *pcap_pkthdr,
                             const uint8_t *packet_data) {
    /* pcap_pkthdr: { ts.tv_sec(32), ts.tv_usec(32), caplen(32), len(32) } */
    if (!a || !pcap_pkthdr || !packet_data) return;
    const uint32_t *hdr = (const uint32_t *)pcap_pkthdr;
    uint32_t caplen = hdr[2];

    record_t *r = (record_t *)calloc(1, sizeof(record_t));
    r->type     = RECORD_PACKET;
    r->data_len = caplen;
    r->data     = (uint8_t *)malloc(caplen);
    if (!r->data) { free(r); return; }
    memcpy(r->data, packet_data, caplen);

    if (a->tail) a->tail->next = r;
    else         a->head = r;
    a->tail = r;
    a->count++;
}

void artifact_save(artifact_t *a) {
    if (!a) return;
    const char *dir = artifact_dir();
    ensure_dir(dir);

    char path[512];
    time_t t = time(NULL);
    snprintf(path, sizeof(path), "%s/%s_%ld.jkya", dir, a->name, (long)t);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[artifact] Cannot open %s: %s\n", path, strerror(errno));
        return;
    }

    /* Header */
    fwrite("JKYA", 4, 1, f);
    write_u16(f, 1);                       /* version */
    uint8_t name_len = (uint8_t)strlen(a->name);
    write_u8(f, name_len);
    fwrite(a->name, name_len, 1, f);
    write_u32(f, a->count);

    /* Records */
    for (record_t *r = a->head; r; r = r->next) {
        write_u8(f,  r->type);
        write_u64(f, r->base_addr);
        write_u32(f, r->protect);
        write_u32(f, r->data_len);
        fwrite(r->data, r->data_len, 1, f);
    }

    fclose(f);
    fprintf(stdout, "[artifact] Saved → %s (%u records)\n", path, a->count);
}

void artifact_free(artifact_t *a) {
    if (!a) return;
    record_t *r = a->head;
    while (r) {
        record_t *next = r->next;
        free(r->data);
        free(r);
        r = next;
    }
    free(a);
}

/* ── Process list ────────────────────────────────────────────────── */
process_list_t *process_list_create(void) {
    process_list_t *l = (process_list_t *)calloc(1, sizeof(process_list_t));
    l->capacity = 64;
    l->entries  = (process_entry_t *)malloc(l->capacity * sizeof(process_entry_t));
    return l;
}

void process_list_add(process_list_t *l, uint32_t pid, const char *name, uint32_t ppid) {
    if (!l) return;
    if (l->count >= l->capacity) {
        l->capacity *= 2;
        l->entries = (process_entry_t *)realloc(l->entries,
                        l->capacity * sizeof(process_entry_t));
    }
    process_entry_t *e = &l->entries[l->count++];
    e->pid  = pid;
    e->ppid = ppid;
    strncpy(e->name, name ? name : "", sizeof(e->name) - 1);
}

void process_list_output(process_list_t *l, const char *filter_expr) {
    if (!l) return;
    printf("%-8s %-8s %s\n", "PID", "PPID", "NAME");
    printf("%-8s %-8s %s\n", "---", "----", "----");
    for (size_t i = 0; i < l->count; i++) {
        process_entry_t *e = &l->entries[i];
        /* Simple substring filter */
        if (filter_expr && strlen(filter_expr) > 0) {
            if (!strstr(e->name, filter_expr)) continue;
        }
        printf("%-8u %-8u %s\n", e->pid, e->ppid, e->name);
    }
}

void process_list_free(process_list_t *l) {
    if (!l) return;
    free(l->entries);
    free(l);
}
