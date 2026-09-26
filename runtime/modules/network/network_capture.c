/*
 * JOCKY Runtime — Network capture module
 * runtime/modules/network/network_capture.c
 *
 * Uses libpcap (cross-platform) in passive/promiscuous-OFF mode.
 * Purely read-only packet capture — no injection, no ARP spoofing.
 *
 * Deps (must be linked): -lpcap  (libpcap / WinPcap / Npcap)
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "../artifacts/artifact.h"

#define DEFAULT_SNAPLEN      65535
#define DEFAULT_READ_TIMEOUT 1000   /* ms */
#define DEFAULT_MAX_PACKETS  10000

/**
 * Passive network capture.
 *
 * @param interface   NIC name ("eth0", "\\Device\\NPF_{...}", NULL → auto)
 * @param filter_bpf  BPF filter string (e.g. "tcp port 443") or NULL
 */
void jocky_scan_network(const char *interface, const char *filter_bpf) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    /* ── Select interface ───────────────────────────────────────── */
    const char *iface = interface;
    if (!iface || strlen(iface) == 0) {
        /* Auto-select first available */
        pcap_if_t *devs = NULL;
        if (pcap_findalldevs(&devs, errbuf) == 0 && devs) {
            iface = devs->name;
        } else {
            fprintf(stderr, "[network] No interfaces found: %s\n", errbuf);
            return;
        }
    }

    fprintf(stdout, "[network] Capturing on interface: %s\n", iface);

    /* ── Open in non-promiscuous mode ───────────────────────────── */
    pcap_t *handle = pcap_open_live(
        iface,
        DEFAULT_SNAPLEN,
        0,                    /* promisc = OFF — non-invasive */
        DEFAULT_READ_TIMEOUT,
        errbuf
    );
    if (!handle) {
        fprintf(stderr, "[network] pcap_open_live failed: %s\n", errbuf);
        return;
    }

    /* ── Apply BPF filter if provided ──────────────────────────── */
    if (filter_bpf && strlen(filter_bpf) > 0) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_bpf, 0, PCAP_NETMASK_UNKNOWN) < 0) {
            fprintf(stderr, "[network] BPF compile error: %s\n", pcap_geterr(handle));
        } else if (pcap_setfilter(handle, &fp) < 0) {
            fprintf(stderr, "[network] BPF setfilter error: %s\n", pcap_geterr(handle));
        } else {
            fprintf(stdout, "[network] BPF filter applied: %s\n", filter_bpf);
        }
        pcap_freecode(&fp);
    }

    /* ── Capture loop ────────────────────────────────────────────── */
    artifact_t *artifact = artifact_create("network_capture");

    struct pcap_pkthdr *header;
    const u_char *packet;
    int count = 0;

    while (count < DEFAULT_MAX_PACKETS) {
        int rc = pcap_next_ex(handle, &header, &packet);
        if (rc == 0)  continue;              /* timeout — keep looping */
        if (rc == -1) {
            fprintf(stderr, "[network] pcap error: %s\n", pcap_geterr(handle));
            break;
        }
        if (rc == -2) break;                 /* EOF (offline capture) */

        artifact_append_packet(artifact, header, packet);
        count++;
    }

    fprintf(stdout, "[network] Captured %d packets\n", count);

    artifact_save(artifact);
    artifact_free(artifact);
    pcap_close(handle);
}

/* ── Interface enumeration (helper for the dashboard) ─────────── */
void jocky_list_interfaces(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL;

    if (pcap_findalldevs(&devs, errbuf) != 0) {
        fprintf(stderr, "[network] pcap_findalldevs: %s\n", errbuf);
        return;
    }

    int i = 1;
    for (pcap_if_t *d = devs; d; d = d->next) {
        printf("%2d. %s", i++, d->name);
        if (d->description) printf(" (%s)", d->description);
        printf("\n");
    }
    pcap_freealldevs(devs);
}
