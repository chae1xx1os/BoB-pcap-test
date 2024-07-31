#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>

Param param = {0};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return -1;
    }
    param.dev_ = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "Can't open device %s: %s\n", param.dev_, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    while (1) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "Error in pcap_next_ex: %s\n", pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)packet;
        struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + sizeof(*eth));
        struct libnet_tcp_hdr* tcp = NULL;

        if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
            printf("Non-IP packet\n");
            continue;
        }

        if (ip->ip_p == IPPROTO_TCP) {
            tcp = (struct libnet_tcp_hdr*)(packet + sizeof(*eth) + ip->ip_hl * 4);
        }

        printf("Ethernet: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x -> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("IP: %s -> %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

        if (tcp) {
            printf("TCP: %d -> %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        }

        int payload_offset = sizeof(*eth) + ip->ip_hl * 4 + (tcp ? tcp->th_off * 4 : 0);
        int payload_length = header->caplen - payload_offset;
        if (payload_length > 0) {
            printf("Payload (%d bytes): ", payload_length > 20 ? 20 : payload_length);
            for (int i = 0; i < (payload_length > 20 ? 20 : payload_length); i++)
                printf("%02x ", packet[payload_offset + i]);
            printf("\n");
        } else {
            printf("No payload\n");
        }
        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
