#include <stdint.h>

#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_short
typedef unsigned short u_short;
#endif
#ifndef u_int
typedef unsigned int u_int;
#endif

struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "../include/packet_analyzer.h"
#include "../include/utils.h"

void init_network_stats(network_stats_t *stats) {
    memset(stats, 0, sizeof(network_stats_t));
    stats->start_time = time(NULL);
    stats->host_count = 0;
    stats->port_count = 0;
    stats->dropped_packets = 0;
    stats->dropped_by_interface = 0;
    stats->dropped_by_kernel = 0;
}

void process_packet(const struct pcap_pkthdr *header, const u_char *packet, network_stats_t *stats) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct iphdr *ip_header;
    struct tcp_header *tcp_header;
    struct udp_header *udp_header;
    char src_ip[16], dst_ip[16];
    uint16_t src_port = 0, dst_port = 0;
    uint8_t protocol = 0;
    
    stats->total_packets++;
    stats->total_bytes += header->len;
    
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        stats->other_packets++;
        return;
    }
    
    ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
    strcpy(src_ip, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    strcpy(dst_ip, inet_ntoa(*(struct in_addr *)&ip_header->daddr));
    protocol = ip_header->protocol;
    
    update_host_stats(stats, src_ip, header->len, 1);
    update_host_stats(stats, dst_ip, header->len, 0);
    
    switch (protocol) {
        case IPPROTO_TCP:
            stats->tcp_packets++;
            tcp_header = (struct tcp_header *)((u_char *)ip_header + (ip_header->ihl * 4));
            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
            update_port_stats(stats, src_port, header->len);
            update_port_stats(stats, dst_port, header->len);
            break;
            
        case IPPROTO_UDP:
            stats->udp_packets++;
            udp_header = (struct udp_header *)((u_char *)ip_header + (ip_header->ihl * 4));
            src_port = ntohs(udp_header->source);
            dst_port = ntohs(udp_header->dest);
            update_port_stats(stats, src_port, header->len);
            update_port_stats(stats, dst_port, header->len);
            break;
            
        case IPPROTO_ICMP:
            stats->icmp_packets++;
            break;
            
        default:
            stats->other_packets++;
            break;
    }
}

void update_host_stats(network_stats_t *stats, const char *ip, uint32_t size, int is_src) {
    int found = 0;
    time_t now = time(NULL);
    
    for (int i = 0; i < stats->host_count; i++) {
        if (strcmp(stats->hosts[i].ip, ip) == 0) {
            if (is_src) {
                stats->hosts[i].packets_sent++;
                stats->hosts[i].bytes_sent += size;
            } else {
                stats->hosts[i].packets_received++;
                stats->hosts[i].bytes_received += size;
            }
            stats->hosts[i].last_seen = now;
            found = 1;
            break;
        }
    }
    
    if (!found && stats->host_count < MAX_HOSTS) {
        strcpy(stats->hosts[stats->host_count].ip, ip);
        if (is_src) {
            stats->hosts[stats->host_count].packets_sent = 1;
            stats->hosts[stats->host_count].bytes_sent = size;
            stats->hosts[stats->host_count].packets_received = 0;
            stats->hosts[stats->host_count].bytes_received = 0;
        } else {
            stats->hosts[stats->host_count].packets_sent = 0;
            stats->hosts[stats->host_count].bytes_sent = 0;
            stats->hosts[stats->host_count].packets_received = 1;
            stats->hosts[stats->host_count].bytes_received = size;
        }
        stats->hosts[stats->host_count].first_seen = now;
        stats->hosts[stats->host_count].last_seen = now;
        stats->host_count++;
    }
}

void update_port_stats(network_stats_t *stats, uint16_t port, uint32_t size) {
    int found = 0;
    time_t now = time(NULL);
    
    for (int i = 0; i < stats->port_count; i++) {
        if (stats->ports[i].port == port) {
            stats->ports[i].connections++;
            stats->ports[i].bytes_transferred += size;
            stats->ports[i].last_activity = now;
            found = 1;
            break;
        }
    }
    
    if (!found && stats->port_count < MAX_PORTS) {
        stats->ports[stats->port_count].port = port;
        stats->ports[stats->port_count].connections = 1;
        stats->ports[stats->port_count].bytes_transferred = size;
        stats->ports[stats->port_count].last_activity = now;
        stats->port_count++;
    }
}

void update_dropped_packets_stats(network_stats_t *stats, pcap_t *handle) {
    struct pcap_stat pstat;
    
    if (pcap_stats(handle, &pstat) == 0) {
        stats->dropped_by_kernel = pstat.ps_drop;
        stats->dropped_by_interface = pstat.ps_ifdrop;
        stats->dropped_packets = pstat.ps_drop + pstat.ps_ifdrop;
    }
}

void print_network_stats(const network_stats_t *stats) {
    time_t now = time(NULL);
    double duration = difftime(now, stats->start_time);
    
    printf("----------------------------------------------------------------\n");
    printf("                        СЕТЕВАЯ СТАТИСТИКА                      \n");
    printf("----------------------------------------------------------------\n");
    printf("Время работы: %.0f сек\n", duration);
    printf("Всего пакетов: %lu\n", stats->total_packets);
    printf("Всего байт: %s\n", format_bytes(stats->total_bytes));
    printf("Скорость пакетов: %s\n", format_packets_per_sec(stats->total_packets, duration));
    printf("Скорость данных: %s\n", format_bytes_per_sec(stats->total_bytes, duration));
    printf("----------------------------------------------------------------\n");
    printf("TCP пакетов: %lu\n", stats->tcp_packets);
    printf("UDP пакетов: %lu\n", stats->udp_packets);
    printf("ICMP пакетов: %lu\n", stats->icmp_packets);
    printf("Других пакетов: %lu\n", stats->other_packets);
    printf("Потерянных пакетов: %lu\n", stats->dropped_packets);
    printf("Потеряно ядром: %lu\n", stats->dropped_by_kernel);
    printf("Потеряно интерфейсом: %lu\n", stats->dropped_by_interface);
    printf("Уникальных хостов: %d\n", stats->host_count);
    printf("Активных портов: %d\n", stats->port_count);
}

void print_host_stats(const network_stats_t *stats) {
    printf("\n----------------------------------------------------------------\n");
    printf("                        СТАТИСТИКА ХОСТОВ                       \n");
    printf("----------------------------------------------------------------\n");
    
    for (int i = 0; i < stats->host_count && i < 20; i++) {
        printf("IP: %s\n", stats->hosts[i].ip);
        printf("Пакетов от этого хоста: %lu\n", stats->hosts[i].packets_sent);
        printf("Пакетов к этому хосту: %lu\n", stats->hosts[i].packets_received);
        printf("Байт от этого хоста: %s\n", format_bytes(stats->hosts[i].bytes_sent));
        printf("Байт к этому хосту: %s\n", format_bytes(stats->hosts[i].bytes_received));
        printf("-----\n");
    }
    
    if (stats->host_count > 20) {
        printf("... и еще %d хостов\n", stats->host_count - 20);
    }
}

void print_port_stats(const network_stats_t *stats) {
    printf("\n----------------------------------------------------------------\n");
    printf("                      СТАТИСТИКА ПОРТОВ                         \n");
    printf("----------------------------------------------------------------\n");
    
    for (int i = 0; i < stats->port_count && i < 20; i++) {
        char time_str[20];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&stats->ports[i].last_activity));
        
        printf("Порт: %d\n", stats->ports[i].port);
        printf("Соединения: %lu\n", stats->ports[i].connections);
        printf("Байт: %s\n", format_bytes(stats->ports[i].bytes_transferred));
        printf("Последняя активность: %s\n", time_str);
        printf("-----\n");
    }
    
    if (stats->port_count > 20) {
        printf("... и еще %d портов\n", stats->port_count - 20);
    }
    printf("----------------------------------------------------------------\n");
} 