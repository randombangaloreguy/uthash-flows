#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "uthash.h"

typedef struct {
        uint32_t src_ip;
        uint32_t dst_ip;
#ifdef USE_L4
        uint16_t src_port;
        uint16_t dst_port;
#endif
        uint8_t proto;
} flow_key_t;

typedef struct {
        flow_key_t key;
        char *data;
        int count;
        UT_hash_handle hh;
} flow_t;

flow_t *records = NULL;
uint32_t total = 0;

flow_t *find_flow(flow_key_t *key) {
        flow_t l, *p;
        memset(&l, 0, sizeof(flow_t));
        l.key.src_ip = key->src_ip;
        l.key.dst_ip = key->dst_ip;
#ifdef USE_L4
        l.key.src_port = key->src_port;
        l.key.dst_port = key->dst_port;
#endif
        l.key.proto = key->proto;
        HASH_FIND(hh, records, &l.key, sizeof(flow_key_t), p);
        return p;
}

void add_flow(flow_key_t *key, char *data) {
        flow_t *r, l, *p;
        flow_t *p_flow = find_flow(key);
        if(p_flow == NULL) {
                r = (flow_t *)malloc(sizeof *r);
                memset(r, 0, sizeof *r);
                r->key.src_ip = key->src_ip;
                r->key.dst_ip = key->dst_ip;
#ifdef USE_L4
                r->key.src_port = key->src_port;
                r->key.dst_port = key->dst_port;
#endif
                r->key.proto = key->proto;
                r->data = strdup(data);
                HASH_ADD(hh, records, key, sizeof(flow_key_t), r);
        } else {
                //update flow
                p_flow->count++;
        }
}

void print_hash_table() {
        flow_t *p, *tmp;
        HASH_ITER(hh, records, p, tmp) {
#ifdef USE_L4
                printf("Key [%x, %x, %d, %d, %d]: Value - %s. Count - %d\n", p->key.src_ip, p->key.dst_ip, p->key.src_port, p->key.dst_port, p->key.proto, p->data, p->count);
#else
                printf("Key [%x, %x, %d]: Value - %s. Count - %d\n", p->key.src_ip, p->key.dst_ip, p->key.proto, p->data, p->count);
#endif
        }
}

void free_hash_table() {
        flow_t *p, *tmp;
        HASH_ITER(hh, records, p, tmp) {
                HASH_DEL(records, p);
                free(p->data);
                free(p);
        }
}

// Function to process each packet
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        total++;
        struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet II framing (14 bytes)
        flow_key_t key = {0};
        uint32_t sip = ip_header->ip_src.s_addr;
        uint32_t dip = ip_header->ip_dst.s_addr;

        // consider key.src_ip as lowIP and key.dst_ip as high IP
        if(sip <= dip) {
                key.src_ip = sip;
                key.dst_ip = dip;
        } else {
                key.src_ip = dip;
                key.dst_ip = sip;
        }
        key.proto = ip_header->ip_p;

#ifdef USE_L4
        uint16_t sport, dport;
        if (key.proto == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
                sport = ntohs(tcp_header->source);
                dport = ntohs(tcp_header->dest);
        }       else if (key.proto == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
                sport = ntohs(udp_header->source);
                dport = ntohs(udp_header->dest);
        } else {
                return; // Ignore non-TCP/UDP packets
        }

        // consider key.src_port as low port and key.dst_port as high port
        if (sport <= dport) {
                key.src_port = sport;
                key.dst_port = dport;
        } else {
                key.src_port = dport;
                key.dst_port = sport;
        }
#endif

        // Add the flow entry to the flow table
        char data[64], source[24], dest[24];
#ifdef USE_L4
        sprintf(source, "%s:%d", inet_ntoa(*(struct in_addr *)&(key.src_ip)), key.src_port);
        sprintf(dest, "%s:%d", inet_ntoa(*(struct in_addr *)&(key.dst_ip)), key.dst_port);
#else
        sprintf(source, "%s", inet_ntoa(*(struct in_addr *)&(key.src_ip)));
        sprintf(dest, "%s", inet_ntoa(*(struct in_addr *)&(key.dst_ip)));
#endif
        sprintf(data, "%s  %s -> %s", (key.proto==6)?"TCP":"UDP", source, dest);
        add_flow(&key, data);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    char *pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", pcap_file, errbuf);
        return 1;
    }

    // Process packets in the pcap file
    pcap_loop(handle, 0, process_packet, NULL);

    print_hash_table();

    // find flow
    flow_key_t key = {0};
#ifdef USE_L4
    key.src_ip = 0xb61ad9ac; key.src_port = 443; //172.217.26.182:443
    key.dst_ip = 0x201a8c0; key.dst_port = 60627;// 198.168.1.2:60627
#else
    key.src_ip = 0xb61ad9ac;  //172.217.26.182
    key.dst_ip = 0x201a8c0;   // 198.168.1.2
#endif
    key.proto = 17;

    flow_t *record = find_flow(&key);
    if (record != NULL) {
            printf("Found FLow. %s\n", record->data);
            printf("%s  %s -> \n", (key.proto==6)?"TCP":"UDP", inet_ntoa(*(struct in_addr *)&(key.src_ip)));
            printf("%s\n", inet_ntoa(*(struct in_addr *)&(key.dst_ip)));
    }

    printf("Total %d packets processed\n", total);
    free_hash_table();
    return 0;
}
