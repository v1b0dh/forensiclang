/*
 * JOCKY Runtime — Memory collection module
 * runtime/modules/memory/memory_collect.c
 *
 * Windows:  OpenProcess + VirtualQueryEx + ReadProcessMemory  (read-only)
 * Linux:    /proc/<pid>/maps + /proc/<pid>/mem                (read-only)
 *
 * DESIGN PRINCIPLES
 * ─────────────────
 *  • NEVER writes to a foreign process.
 *  • Uses only standard, documented OS APIs.
 *  • Every allocation is paired with a matching free().
 *  • Produces a .jkya artifact file via artifact_save().
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../artifacts/artifact.h"

/* ═══════════════════════════════════════════════════════════════
 * WINDOWS IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════ */
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>

void jocky_collect_memory(int64_t pid, const char *export_name) {
    HANDLE process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        (DWORD)pid
    );
    if (!process) {
        fprintf(stderr, "[memory] OpenProcess(%lld) failed: %lu\n",
                pid, GetLastError());
        return;
    }

    artifact_t *artifact = artifact_create(export_name);
    if (!artifact) { CloseHandle(process); return; }

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    SIZE_T total_bytes = 0;

    while (VirtualQueryEx(process, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        /* Only capture committed, private/mapped pages — skip guard/noaccess */
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type  == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0) {

            uint8_t *buffer = (uint8_t *)malloc(mbi.RegionSize);
            if (!buffer) goto next_region;

            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(process, mbi.BaseAddress,
                                  buffer, mbi.RegionSize, &bytes_read) &&
                bytes_read > 0) {
                artifact_append_region(artifact,
                    (uint64_t)(uintptr_t)mbi.BaseAddress,
                    buffer, bytes_read,
                    mbi.Protect);
                total_bytes += bytes_read;
            }
            free(buffer);
        }
next_region:
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    fprintf(stdout, "[memory] Captured %zu bytes from PID %lld\n",
            total_bytes, pid);

    artifact_save(artifact);
    artifact_free(artifact);
    CloseHandle(process);
}

/* ── Process scanner (Windows) ────────────────────────────────── */
void jocky_scan_processes(const char *filter_expr) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[scan] CreateToolhelp32Snapshot failed: %lu\n",
                GetLastError());
        return;
    }

    process_list_t *list = process_list_create();

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &pe)) {
        do {
            process_list_add(list, pe.th32ProcessID,
                             pe.szExeFile, pe.th32ParentProcessID);
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    process_list_output(list, filter_expr);
    process_list_free(list);
}

/* ═══════════════════════════════════════════════════════════════
 * LINUX IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════ */
#else /* _WIN32 */
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>

void jocky_collect_memory_linux(int64_t pid, const char *export_name) {
    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%lld/maps", pid);
    snprintf(mem_path,  sizeof(mem_path),  "/proc/%lld/mem",  pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        fprintf(stderr, "[memory] Cannot open %s\n", maps_path);
        return;
    }
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "[memory] Cannot open %s\n", mem_path);
        fclose(maps);
        return;
    }

    artifact_t *artifact = artifact_create(export_name);
    size_t total_bytes = 0;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3) continue;
        if (perms[0] != 'r') continue;           /* skip non-readable */

        size_t size = end - start;
        if (size == 0 || size > 256 * 1024 * 1024) continue; /* skip huge/zero */

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;

        ssize_t n = pread(mem_fd, buf, size, (off_t)start);
        if (n > 0) {
            artifact_append_region(artifact, (uint64_t)start,
                                   buf, (size_t)n, 0);
            total_bytes += (size_t)n;
        }
        free(buf);
    }

    fprintf(stdout, "[memory] Captured %zu bytes from PID %lld\n",
            total_bytes, pid);

    artifact_save(artifact);
    artifact_free(artifact);
    fclose(maps);
    close(mem_fd);
}

/* Provide a no-op Windows stub so the IR link target exists on Linux */
void jocky_collect_memory(int64_t pid, const char *export_name) {
    jocky_collect_memory_linux(pid, export_name);
}

/* ── Process scanner (Linux — /proc) ─────────────────────────── */
void jocky_scan_processes(const char *filter_expr) {
    DIR *proc = opendir("/proc");
    if (!proc) { perror("[scan] opendir /proc"); return; }

    process_list_t *list = process_list_create();

    struct dirent *entry;
    while ((entry = readdir(proc))) {
        /* Only numeric entries are PIDs */
        const char *d = entry->d_name;
        int is_pid = 1;
        for (const char *c = d; *c; c++) {
            if (!isdigit((unsigned char)*c)) { is_pid = 0; break; }
        }
        if (!is_pid || d[0] == '\0') continue;

        int pid_val = atoi(d);
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid_val);
        FILE *cf = fopen(comm_path, "r");
        char comm[256] = {0};
        if (cf) {
            if (!fgets(comm, sizeof(comm), cf)) comm[0] = '\0';
            /* strip trailing newline */
            comm[strcspn(comm, "\n")] = '\0';
            fclose(cf);
        }

        /* Read ppid from /proc/<pid>/status */
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid_val);
        FILE *sf = fopen(status_path, "r");
        uint32_t ppid = 0;
        if (sf) {
            char line[256];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "PPid:", 5) == 0) {
                    ppid = (uint32_t)atoi(line + 5);
                    break;
                }
            }
            fclose(sf);
        }

        process_list_add(list, (uint32_t)pid_val, comm, ppid);
    }
    closedir(proc);

    process_list_output(list, filter_expr);
    process_list_free(list);
}

#endif /* _WIN32 */
