#ifndef PCAP_TEST_H
#define PCAP_TEST_H

#include <pcap.h>
#include <libnet.h>

typedef struct {
    char* dev_;
} Param;

extern Param param;

void print_hex(const u_char* data, int len);

#endif