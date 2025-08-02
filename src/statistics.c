#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "../include/statistics.h"
#include "../include/utils.h"

void init_stats_collector(stats_collector_t *collector, int interval) {
    memset(collector, 0, sizeof(stats_collector_t));
    init_network_stats(&collector->stats);
    pthread_mutex_init(&collector->mutex, NULL);
    collector->interval = interval;
    collector->running = 0;
}

void destroy_stats_collector(stats_collector_t *collector) {
    if (collector->running) {
        stop_stats_collection(collector);
    }
    pthread_mutex_destroy(&collector->mutex);
}

void start_stats_collection(stats_collector_t *collector) {
    collector->running = 1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, stats_collector_thread, collector) != 0) {
        fprintf(stderr, "Ошибка создания потока статистики\n");
        return;
    }
    pthread_detach(thread);
}

void stop_stats_collection(stats_collector_t *collector) {
    collector->running = 0;
}

void *stats_collector_thread(void *arg) {
    stats_collector_t *collector = (stats_collector_t *)arg;
    
    while (collector->running) {
        sleep(collector->interval);
        if (collector->running) {
            print_realtime_stats(collector);
        }
    }
    
    return NULL;
}

void print_realtime_stats(const stats_collector_t *collector) {
    network_stats_t stats_copy;
    
    pthread_mutex_lock((pthread_mutex_t *)&collector->mutex);
    memcpy(&stats_copy, &collector->stats, sizeof(network_stats_t));
    pthread_mutex_unlock((pthread_mutex_t *)&collector->mutex);
    
    time_t now = time(NULL);
    double duration = difftime(now, stats_copy.start_time);
    
    printf("\n[%s] ", ctime(&now));
    printf("Пакетов: %lu | Байт: %s | Скорость: %s | Хостов: %d | Порт: %d\n",
           stats_copy.total_packets,
           format_bytes(stats_copy.total_bytes),
           format_packets_per_sec(stats_copy.total_packets, duration),
           stats_copy.host_count,
           stats_copy.port_count);
    
    printf("TCP: %lu | UDP: %lu | ICMP: %lu | Другие: %lu\n",
           stats_copy.tcp_packets,
           stats_copy.udp_packets,
           stats_copy.icmp_packets,
           stats_copy.other_packets);
}

void print_summary_report(const stats_collector_t *collector) {
    printf("\n");
    print_network_stats(&collector->stats);
    print_host_stats(&collector->stats);
    print_port_stats(&collector->stats);
} 