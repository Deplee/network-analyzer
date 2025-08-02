#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_short
typedef unsigned short u_short;
#endif
#ifndef u_int
typedef unsigned int u_int;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include "../include/utils.h"
#include "../include/statistics.h"

char *format_bytes(uint64_t bytes) {
    static char buffer[32];
    memset(buffer, 0, sizeof(buffer));
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = bytes;
    
    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }
    
    if (unit_index == 0) {
        snprintf(buffer, sizeof(buffer), "%lu %s", bytes, units[unit_index]);
    } else {
        snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unit_index]);
    }
    
    return buffer;
}

char *format_packets_per_sec(uint64_t packets, double seconds) {
    static char buffer[32];
    if (seconds <= 0) {
        snprintf(buffer, sizeof(buffer), "0 pkt/s");
    } else {
        double pps = packets / seconds;
        if (pps >= 1000000) {
            snprintf(buffer, sizeof(buffer), "%.2f M pkt/s", pps / 1000000);
        } else if (pps >= 1000) {
            snprintf(buffer, sizeof(buffer), "%.2f K pkt/s", pps / 1000);
        } else {
            snprintf(buffer, sizeof(buffer), "%.2f pkt/s", pps);
        }
    }
    return buffer;
}

char *format_bytes_per_sec(uint64_t bytes, double seconds) {
    static char buffer[32];
    if (seconds <= 0) {
        snprintf(buffer, sizeof(buffer), "0 B/s");
    } else {
        double bps = bytes / seconds;
        if (bps >= 1073741824.0) {
            snprintf(buffer, sizeof(buffer), "%.2f GB/s", bps / 1073741824.0);
        } else if (bps >= 1048576.0) {
            snprintf(buffer, sizeof(buffer), "%.2f MB/s", bps / 1048576.0);
        } else if (bps >= 1024.0) {
            snprintf(buffer, sizeof(buffer), "%.2f KB/s", bps / 1024.0);
        } else {
            snprintf(buffer, sizeof(buffer), "%.2f B/s", bps);
        }
    }
    return buffer;
}

int validate_interface(const char *interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return 0;
    }
    
    close(sock);
    return (ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING);
}

void list_interfaces(void) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Ошибка поиска интерфейсов: %s\n", errbuf);
        return;
    }
    
    printf("Доступные сетевые интерфейсы:\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ %-20s %-40s ║\n", "Интерфейс", "Описание");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("║ %-20s %-40s ║\n", d->name, d->description ? d->description : "Нет описания");
    }
    
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    pcap_freealldevs(alldevs);
}

void cleanup_resources(void) {
    printf("Очистка ресурсов...\n");
}

void cleanup_network_analyzer(pcap_t *handle, stats_collector_t *collector) {
    if (collector) {
        destroy_stats_collector(collector);
    }
    if (handle) {
        pcap_close(handle);
    }
} 