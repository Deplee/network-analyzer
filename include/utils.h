#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

void print_usage(const char *program_name);
void print_version(void);
void signal_handler(int sig);
char *format_bytes(uint64_t bytes);
char *format_packets_per_sec(uint64_t packets, double seconds);
char *format_bytes_per_sec(uint64_t bytes, double seconds);
void print_banner(void);
int validate_interface(const char *interface);
void list_interfaces(void);
void cleanup_resources(void);

extern volatile int running;

#endif
