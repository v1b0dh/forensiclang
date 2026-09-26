/*
 * JOCKY Runtime — Disk collection module
 * runtime/modules/disk/disk_collect.c
 *
 * Windows:  Volume Shadow Copy Service (VSS) — point-in-time snapshot,
 *           then read MFT / files from the frozen volume.
 * Linux:    Direct /dev/sdX or dd-style block read; no kernel modules needed.
 *
 * DESIGN: read-only, non-destructive, VSS avoids live-file access heuristics.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../artifacts/artifact.h"

/* ═══════════════════════════════════════════════════════════════
 * WINDOWS IMPLEMENTATION (VSS)
 * ═══════════════════════════════════════════════════════════════ */
#ifdef _WIN32
#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

/*
 * Forward declaration — actual MFT parser is in disk_mft.c
 * Signature: void disk_read_mft(const wchar_t* device, const char* export_name)
 */
extern void disk_read_mft(const wchar_t *device, const char *export_name);

static void log_err(const char *msg, HRESULT hr) {
    fprintf(stderr, "[disk] %s (HRESULT=0x%08lX)\n", msg, (unsigned long)hr);
}

/**
 * Create a VSS snapshot, read MFT from the frozen volume, then delete snapshot.
 * volume: e.g. "C:\\" or L"C:\\"
 */
void jocky_collect_disk_vss(const char *volume, const char *export_name) {
    HRESULT hr;

    /* Convert volume to wide string */
    wchar_t wvol[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, volume, -1, wvol, MAX_PATH);

    /* Initialise COM */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        log_err("CoInitializeEx failed", hr); return;
    }

    IVssBackupComponents *backup = NULL;
    hr = CreateVssBackupComponents(&backup);
    if (FAILED(hr)) { log_err("CreateVssBackupComponents", hr); goto cleanup_com; }

    hr = backup->lpVtbl->InitializeForBackup(backup, NULL);
    if (FAILED(hr)) { log_err("InitializeForBackup", hr); goto cleanup_vss; }

    hr = backup->lpVtbl->SetBackupState(
        backup, FALSE, FALSE, VSS_BT_COPY, FALSE);
    if (FAILED(hr)) { log_err("SetBackupState", hr); goto cleanup_vss; }

    IVssAsync *async = NULL;
    hr = backup->lpVtbl->GatherWriterMetadata(backup, &async);
    if (SUCCEEDED(hr)) { async->lpVtbl->Wait(async, INFINITE); async->lpVtbl->Release(async); }

    VSS_ID snapshot_id;
    hr = backup->lpVtbl->AddToSnapshotSet(backup, wvol, (GUID)GUID_NULL, &snapshot_id);
    if (FAILED(hr)) { log_err("AddToSnapshotSet", hr); goto cleanup_vss; }

    hr = backup->lpVtbl->PrepareForBackup(backup, &async);
    if (SUCCEEDED(hr)) { async->lpVtbl->Wait(async, INFINITE); async->lpVtbl->Release(async); }

    hr = backup->lpVtbl->DoSnapshotSet(backup, &async);
    if (SUCCEEDED(hr)) { async->lpVtbl->Wait(async, INFINITE); async->lpVtbl->Release(async); }

    /* Retrieve the snapshot device path and read from it */
    VSS_SNAPSHOT_PROP snap_prop;
    hr = backup->lpVtbl->GetSnapshotProperties(backup, snapshot_id, &snap_prop);
    if (SUCCEEDED(hr)) {
        /* snap_prop.m_pwszSnapshotDeviceObject →
         * \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN */
        disk_read_mft(snap_prop.m_pwszSnapshotDeviceObject, export_name);
        VssFreeSnapshotProperties(&snap_prop);
    } else {
        log_err("GetSnapshotProperties", hr);
    }

    /* Tear down the snapshot — mandatory cleanup */
    LONG deleted = 0;
    VSS_ID non_deleted;
    backup->lpVtbl->DeleteSnapshots(
        backup, snapshot_id, VSS_OBJECT_SNAPSHOT, TRUE, &deleted, &non_deleted);

cleanup_vss:
    backup->lpVtbl->Release(backup);
cleanup_com:
    CoUninitialize();
}

/* ── MFT stub (full parser in disk_mft.c) ────────────────────── */
void disk_read_mft(const wchar_t *device, const char *export_name) {
    /* TODO: Implement $MFT raw parser */
    wprintf(L"[disk] Reading MFT from %ls → %hs\n", device, export_name);

    artifact_t *a = artifact_create(export_name);
    /* For now emit a placeholder; Phase 3 extension: parse $MFT records */
    const char placeholder[] = "MFT_PLACEHOLDER";
    artifact_append_region(a, 0, (const uint8_t *)placeholder,
                            sizeof(placeholder), 0);
    artifact_save(a);
    artifact_free(a);
}

/* ── Registry collection (Windows) ───────────────────────────── */
void jocky_collect_registry(const char *hive_path, const char *export_name) {
    HKEY root = HKEY_LOCAL_MACHINE;
    if (strncmp(hive_path, "HKCU", 4) == 0) root = HKEY_CURRENT_USER;
    if (strncmp(hive_path, "HKCR", 4) == 0) root = HKEY_CLASSES_ROOT;

    HKEY key;
    wchar_t wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, hive_path, -1, wpath, MAX_PATH);

    artifact_t *a = artifact_create(export_name);

    LONG rc = RegOpenKeyExW(root, wpath, 0, KEY_READ, &key);
    if (rc == ERROR_SUCCESS) {
        DWORD idx = 0;
        wchar_t name[256];
        BYTE   data[4096];
        DWORD  name_len, data_len, type;

        /* Enumerate values */
        while (TRUE) {
            name_len = 256; data_len = 4096;
            rc = RegEnumValueW(key, idx++, name, &name_len, NULL,
                               &type, data, &data_len);
            if (rc != ERROR_SUCCESS) break;
            artifact_append_region(a, (uint64_t)type,
                                   data, data_len, 0);
        }
        RegCloseKey(key);
    } else {
        fprintf(stderr, "[disk] RegOpenKeyEx failed: %ld\n", rc);
    }

    artifact_save(a);
    artifact_free(a);
}

/* ═══════════════════════════════════════════════════════════════
 * LINUX IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════ */
#else /* _WIN32 */
#include <fcntl.h>
#include <unistd.h>

#define BLOCK_SIZE (4096UL)
#define MAX_BLOCKS (1024UL * 256UL)   /* 1 GB cap for safety */

void jocky_collect_disk_vss(const char *device, const char *export_name) {
    /* On Linux, "volume" is a block device path, e.g. /dev/sda1 */
    int fd = open(device, O_RDONLY);
    if (fd < 0) {
        perror("[disk] open device");
        return;
    }

    artifact_t *a = artifact_create(export_name);
    uint8_t buf[BLOCK_SIZE];
    size_t  total = 0;
    uint64_t lba  = 0;

    for (size_t blk = 0; blk < MAX_BLOCKS; blk++) {
        ssize_t n = read(fd, buf, BLOCK_SIZE);
        if (n <= 0) break;
        artifact_append_region(a, lba, buf, (size_t)n, 0);
        lba   += (uint64_t)n;
        total += (size_t)n;
    }

    fprintf(stdout, "[disk] Read %zu bytes from %s\n", total, device);
    artifact_save(a);
    artifact_free(a);
    close(fd);
}

/* Stub */
void jocky_collect_registry(const char *hive_path, const char *export_name) {
    fprintf(stderr, "[disk] Registry collection not available on Linux\n");
}

#endif /* _WIN32 */
