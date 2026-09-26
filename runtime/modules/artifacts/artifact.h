/*
 * JOCKY Runtime — Artifact system (header)
 * runtime/modules/artifacts/artifact.h
 *
 * Artifacts are the outputs of every JOCKY collection operation.
 * They store raw forensic data in a compact, self-describing format.
 */
#pragma once
#ifndef JOCKY_ARTIFACT_H
#define JOCKY_ARTIFACT_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque artifact handle ─────────────────────────────────────── */
typedef struct artifact_s artifact_t;

/* ── Network-packet entry (for pcap output) ──────────────────────── */
typedef struct {
    uint64_t  ts_sec;
    uint64_t  ts_usec;
    uint32_t  cap_len;
    uint32_t  orig_len;
    uint8_t  *data;
} jocky_packet_t;

/* ── Process list (for scan processes output) ────────────────────── */
typedef struct process_entry_s {
    uint32_t pid;
    uint32_t ppid;
    char     name[260];
} process_entry_t;

typedef struct {
    process_entry_t *entries;
    size_t           count;
    size_t           capacity;
} process_list_t;

/* ── Artifact API ────────────────────────────────────────────────── */

/**
 * Create a new artifact with the given name.
 * Returns a heap-allocated handle; caller must call artifact_free().
 */
artifact_t *artifact_create(const char *name);

/**
 * Append a raw memory region to the artifact.
 *  base_addr  — virtual address of the region in the source process
 *  data       — bytes to store
 *  size       — number of bytes
 *  protect    — Windows MEMORY_BASIC_INFORMATION.Protect flag (0 on Linux)
 */
void artifact_append_region(artifact_t *a,
                             uint64_t    base_addr,
                             const uint8_t *data,
                             size_t      size,
                             uint32_t    protect);

/**
 * Append a captured network packet.
 */
void artifact_append_packet(artifact_t *a,
                             const void *pcap_pkthdr,
                             const uint8_t *packet_data);

/**
 * Serialize the artifact to disk under JOCKY_ARTIFACT_DIR
 * (default: ./jocky_artifacts/).
 */
void artifact_save(artifact_t *a);

/**
 * Free all resources associated with an artifact handle.
 * The caller must NOT use the pointer after this call.
 */
void artifact_free(artifact_t *a);

/* ── Process list helpers ────────────────────────────────────────── */
process_list_t *process_list_create(void);
void            process_list_add(process_list_t *l, uint32_t pid,
                                  const char *name, uint32_t ppid);
void            process_list_output(process_list_t *l, const char *filter_expr);
void            process_list_free(process_list_t *l);

#ifdef __cplusplus
}
#endif

#endif /* JOCKY_ARTIFACT_H */
