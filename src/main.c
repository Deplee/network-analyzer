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
#include <sys/types.h>
#include <pcap.h>
#include <pthread.h>
#include "../include/packet_analyzer.h"
#include "../include/statistics.h"
#include "../include/utils.h"

volatile int running = 1;
pcap_t *handle = NULL;

void signal_handler(int sig) {
    printf("\nПолучен сигнал %d, завершение работы...\n", sig);
    running = 0;
    if (handle) {
        pcap_breakloop(handle);
    }
}

void print_usage(const char *program_name) {
    printf("Использование: %s [опции] <интерфейс>\n", program_name);
    printf("Опции:\n");
    printf("  -h, --help           Показать эту справку\n");
    printf("  -v, --version        Показать версию\n");
    printf("  -i <секунды>         Интервал обновления статистики (по умолчанию: 5)\n");
    printf("  -f <файл>            Фильтр pcap (например: 'tcp port 80')\n");
    printf("  -l                   Список доступных интерфейсов\n");
    printf("  -s                   Показать статистику в реальном времени\n");
    printf("\nПримеры:\n");
    printf("  %s eth0                    # Анализ трафика на eth0\n", program_name);
    printf("  %s -i 10 eth0              # Обновление каждые 10 секунд\n", program_name);
    printf("  %s -f 'tcp port 80' eth0   # Только HTTP трафик\n", program_name);
}

void print_version(void) {
    printf("Network Analyzer v1.0.0\n");
    printf("Анализатор сетевого трафика\n");
}

void print_banner(void) {
    printf("╔═════════════════════════════════════════════════════════════╗\n");
    printf("║                    NETWORK ANALYZER v1.0.0                  ║\n");
    printf("║                Анализатор сетевого трафика                  ║\n");
    printf("╚═════════════════════════════════════════════════════════════╝\n");
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *filter = NULL;
    int interval = 5;
    int show_realtime = 0;
    (void)show_realtime;
    char errbuf[PCAP_ERRBUF_SIZE];
    stats_collector_t collector;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                interval = atoi(argv[++i]);
                if (interval <= 0) {
                    fprintf(stderr, "Ошибка: интервал должен быть положительным числом\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "Ошибка: не указан интервал для -i\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                filter = argv[++i];
            } else {
                fprintf(stderr, "Ошибка: не указан фильтр для -f\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-l") == 0) {
            list_interfaces();
            return 0;
        } else if (strcmp(argv[i], "-s") == 0) {
            show_realtime = 1;
        } else if (argv[i][0] != '-') {
            interface = argv[i];
        } else {
            fprintf(stderr, "Неизвестная опция: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (!interface) {
        fprintf(stderr, "Ошибка: не указан сетевой интерфейс\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (!validate_interface(interface)) {
        fprintf(stderr, "Ошибка: интерфейс '%s' недоступен\n", interface);
        return 1;
    }
    
    print_banner();
    printf("Запуск анализатора на интерфейсе: %s\n", interface);
    if (filter) {
        printf("Применен фильтр: %s\n", filter);
    }
    printf("Интервал обновления: %d секунд\n", interval);
    printf("Нажмите Ctrl+C для остановки\n\n");
    
    handle = pcap_open_live(interface, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Ошибка открытия интерфейса: %s\n", errbuf);
        return 1;
    }
    
    if (filter) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Ошибка компиляции фильтра: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Ошибка установки фильтра: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 1;
        }
    }
    
    init_stats_collector(&collector, interval);
    start_stats_collection(&collector);
    
    struct pcap_pkthdr header;
    const u_char *packet;
    
    while (running) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) {
            continue;
        }
        
        pthread_mutex_lock(&collector.mutex);
        process_packet(&header, packet, &collector.stats);
        update_dropped_packets_stats(&collector.stats, handle);
        pthread_mutex_unlock(&collector.mutex);
    }
    
    printf("\nЗавершение работы...\n");
    stop_stats_collection(&collector);
    print_summary_report(&collector);
    destroy_stats_collector(&collector);
    pcap_close(handle);
    
    return 0;
} 