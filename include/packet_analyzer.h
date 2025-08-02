#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_short
typedef unsigned short u_short;
#endif
#ifndef u_int
typedef unsigned int u_int;
#endif

#include <sys/types.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_PACKET_SIZE 65536
#define MAX_HOSTS 1000
#define MAX_PORTS 65536

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t packet_size;
    time_t timestamp;
} packet_info_t;

typedef struct {
    char ip[16];
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    time_t first_seen;
    time_t last_seen;
} host_stats_t;

typedef struct {
    uint16_t port;
    uint64_t connections;
    uint64_t bytes_transferred;
    time_t last_activity;
} port_stats_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    uint64_t dropped_packets;
    uint64_t dropped_by_interface;
    uint64_t dropped_by_kernel;
    host_stats_t hosts[MAX_HOSTS];
    int host_count;
    port_stats_t ports[MAX_PORTS];
    int port_count;
    time_t start_time;
} network_stats_t;

void init_network_stats(network_stats_t *stats);
void process_packet(const struct pcap_pkthdr *header, const u_char *packet, network_stats_t *stats);
void print_network_stats(const network_stats_t *stats);
void print_host_stats(const network_stats_t *stats);
void print_port_stats(const network_stats_t *stats);
void update_host_stats(network_stats_t *stats, const char *ip, uint32_t size, int is_src);
void update_port_stats(network_stats_t *stats, uint16_t port, uint32_t size);
void update_dropped_packets_stats(network_stats_t *stats, pcap_t *handle);

#endif 