#ifndef STATISTICS_H
#define STATISTICS_H

#include <time.h>
#include <pthread.h>
#include "packet_analyzer.h"

typedef struct {
    network_stats_t stats;
    pthread_mutex_t mutex;
    int running;
    int interval;
} stats_collector_t;

void init_stats_collector(stats_collector_t *collector, int interval);
void destroy_stats_collector(stats_collector_t *collector);
void start_stats_collection(stats_collector_t *collector);
void stop_stats_collection(stats_collector_t *collector);
void *stats_collector_thread(void *arg);
void print_realtime_stats(const stats_collector_t *collector);
void print_summary_report(const stats_collector_t *collector);

#endif 