/*
 *  Created by Grant Campanelli on 4/8/15.
 *  Trace.c
 *
 *
 */

#include <pcap/pcap.h>
#include "trace.h"
#include "checksum.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void printMacAddr(unsigned char * addr) {
    int i = 0;

    for(i = 0; i < ARP_MAC_ADDR_LEN; i++) {
        if(i)
            printf(":");
        printf("%x", addr[i]);
    }
}

void printIPAddr(unsigned char * addr) {
    int i = 0;

    for(i = 0; i < ARP_IP_ADDR_LEN; i++) {
        if(i)
            printf(".");
        printf("%u", addr[i]);
    }
};

void arpRead(const unsigned char *packet) {
    struct sniff_arp *arp = malloc(sizeof(struct sniff_arp));
    memcpy(arp, packet + ETHER_SIZE, sizeof(struct sniff_arp));
    printf("\tARP header\n");
    if(endian(arp->arp_opcode) & 2)
        printf("\t\tOpcode: Reply\n");
    else
        printf("\t\tOpcode: Request\n");

    printf("\t\tSender MAC: ");
    printMacAddr(arp->arp_send_mac_addr);
    printf("\n\t\tSender IP: ");
    printIPAddr(arp->arp_send_ip_addr);
    printf("\n\t\tTarget MAC: ");
    printMacAddr(arp->arp_targ_mac_addr);
    printf("\n\t\tTarget IP: ");
    printIPAddr(arp->arp_targ_ip_addr);
    printf("\n\n");
}

void ethernetRead(const unsigned char *packet, struct pcap_pkthdr header) {
    struct sniff_ethernet *eth = malloc(sizeof(struct sniff_ethernet));
    memcpy(eth, packet, sizeof(struct sniff_ethernet));
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: ");
    printMacAddr(eth->eth_dest);
    printf("\n\t\tSource MAC: ");
    printMacAddr(eth->eth_src);

    printf("\n\t\tType: ");

    // fix this
    if(eth->eth_type == ARP_FLAG) {
        printf("ARP\n\n");
        arpRead(packet);
    }
    else if(eth->eth_type == IP_FLAG) {
        printf("IP\n\n");
        ipRead(packet, header);
    }
    else {
        printf("Unkown\n\n");
    }

}

void ipRead(const unsigned char *packet, struct pcap_pkthdr header) {
    struct sniff_ip *ip = malloc(sizeof(struct sniff_ip));
    int flag = 0, len;
    // unsigned char * pointer = ip;
    memcpy(ip, packet + ETHER_SIZE, sizeof(struct sniff_ip));
    int checksum = 0;
    printf("\tIP Header\n");
    printf("\t\tTOS: 0x%x\n", ip->ip_tos);
    printf("\t\tTTL: %u\n", ip->ip_ttl);
    printf("\t\tProtocol: ");

    //printf("%02x\n", ip->ip_protocol);
    switch(ip->ip_protocol) {
        case IP_ICMP:
            printf("ICMP\n");
            flag = 1;
            break;
        case IP_TCP:
            printf("TCP\n");
            flag = 2;
            break;
        case IP_UDP:
            printf("UDP\n");
            flag = 3;
            break;
        default:
            printf("Unknown\n");
            flag = -1;
            break;
    }

    len = 4 * ((* (packet + ETHER_SIZE)) & IP_IHL);
    checksum = in_cksum((unsigned short *) ip, len);
    if(!checksum)
        printf("\t\tChecksum: Correct (0x%x)\n", endian(ip->ip_sum));
    else
        printf("\t\tChecksum: Incorrect (0x%x)\n", endian(ip->ip_sum));

    printf("\t\tSender IP: ");
    printIPAddr(ip->ip_source);
    printf("\n\t\tDest IP: ");
    printIPAddr(ip->ip_dest);
    printf("\n");

    ipDistribute(packet, flag, ip, len);
}

void ipDistribute(const unsigned char *packet, int flag, struct sniff_ip *ip, int length){

    switch(flag) {
        case 1:
            icmpRead(packet, ntohs(ip->ip_len)-length);
            break;
        case 2:
            tcpRead(packet, ip, ntohs(ip->ip_len)-length);
            break;
        case 3:
            udpRead(packet);
            break;
        default:
            break;
    }
}

void icmpRead(const unsigned char *packet, unsigned short length) {
    struct sniff_ip * ip = (struct sniff_ip *)(packet + ETHER_SIZE);
    unsigned char * addr = ((unsigned char *)packet + ETHER_SIZE + (IP_HL(ip) * 4));
    unsigned char type = (unsigned char)*addr;
    printf("\n\tICMP Header\n");

    switch(type) {
        case IP_ICMP_REQUEST:
            printf("\t\tType: Request\n");
            break;
        case IP_ICMP_REPLY:
            printf("\t\tType: Reply\n");
            break;
        default:
            printf("\t\tType: Unknown\n");
            break;
    }
}

/*
 * Send a pointer to where pseudo header and TCP is
 * make chunk somerwhere to put the pseudo header htne the tcp
 * check (addr at beginning, length which is 12 + (ip total - ip header))
 */

void tcpCheckSumRead(struct sniff_tcp * tcp, struct sniff_ip * ip, struct tcp_pseudo_header * tcpPseudoHeader,
                     unsigned short length) {
    unsigned int checksum;
    uint8_t pseudo[SIZE_PSEUDO];
    uint8_t tcpWithPseudo[length + SIZE_PSEUDO];

    memcpy(pseudo, ip->ip_source, IP_ADDR_LENGTH);
    memcpy(pseudo + IP_ADDR_LENGTH, ip->ip_dest, IP_ADDR_LENGTH);
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10] = length >> 8;
    pseudo[11] = length & 0x00FF;
    //memcpy(pseudo + IP_ADDR_LENGTH + 1, 0, IP_ADDR_LENGTH);
    //tcpPseudoHeader->pad = 0;
    //tcpPseudoHeader->protocol = 6;
    //tcpPseudoHeader->len = length;

    //memcpy(tcpWithPseudo, tcpPseudoHeader, SIZE_PSEUDO);
    memcpy(tcpWithPseudo, pseudo, SIZE_PSEUDO);
    memcpy(tcpWithPseudo + SIZE_PSEUDO, tcp, length);

    //printf("ipTotal  - ipHeader: %u - %u = %u\n", ntohs(ip->ip_len),  4*(IP_HL(ip)),  length);
//    for(i=0; i< length + SIZE_PSEUDO; i++) {
//        printf("%x", tcpWithPseudo[i]);
//    }

    checksum = in_cksum((unsigned short *)tcpWithPseudo, (length + SIZE_PSEUDO));
    if(!checksum)
        printf("\t\tChecksum: Correct (0x%x)\n", endian(tcp->tcp_checksum));
    else
        printf("\t\tChecksum: Incorrect (0x%x)\n", endian(tcp->tcp_checksum));
}

void tcpPrintFlags(struct sniff_tcp * tcp) {
    char * s = "No", *r = "No", *f = "No";
    if(tcp->tcp_flags & TCP_SYN)
        s = "Yes";
    if(tcp->tcp_flags & TCP_RST)
        r = "Yes";
    if(tcp->tcp_flags & TCP_FIN)
        f = "Yes";
    printf("\t\tSYN Flag: %s\n", s);
    printf("\t\tRST Flag: %s\n", r);
    printf("\t\tFIN Flag: %s\n", f);
}

void printTCPSourcePorts(struct sniff_tcp *tcp) {
    char * source;
    switch(endian(tcp->tcp_src)) {
        case FTP_P20:
            source = "FTP";
            break;
        case FTP_P21:
            source = "FTP";
            break;
        case SMTP:
            source = "SMTP";
            break;
        case HTTP:
            source = "HTTP";
            break;
        case POP3:
            source = "POP3";
            break;
        default:
            printf("\t\tSource Port:  %u\n", endian(tcp->tcp_src));
            return;
    }
    printf("\t\tSource Port:  %s\n", source);
}

void printTCPDestPorts(struct sniff_tcp *tcp) {
    char * destination;
    switch(endian(tcp->tcp_dest)) {
        case FTP_P20:
            destination = "FTP";
            break;
        case FTP_P21:
            destination = "FTP";
            break;
        case SMTP:
            destination = "SMTP";
            break;
        case HTTP:
            destination = "HTTP";
            break;
        case POP3:
            destination = "POP3";
            break;
        default:
            printf("\t\tDest Port:  %u\n", endian(tcp->tcp_dest));
            return;
    }
    printf("\t\tDest Port:  %s\n", destination);
}

/*
 * Send a pointer to where pseudo header and TCP is
 * make chunk somerwhere to put the pseudo header htne the tcp
 * check (addr at beginning, length which is 12 + (ip total - ip header))
 */

void tcpRead(const unsigned char *packet, struct sniff_ip *ip, int length) {
    struct sniff_tcp *tcp = (struct sniff_tcp *)
            (packet +  sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
    struct tcp_pseudo_header *tcpPseudoHeader = malloc(SIZE_PSEUDO);
    unsigned short len;
    //pesudo header is always 12
    //ip total - ip header
    len = ntohs(ip->ip_len) - (4*(IP_HL(ip)));
    //printf("ipTotal  - ipHeader: %u - %u = %u\n", ntohs(ip->ip_len),  4*(IP_HL(ip)),  len);
    //printf("ipSize: %i\ntcpSize %x\n", 4*(IP_HL(ip)), tcpSize);

    //printf("ip total: %u\nip len %x\n", len, endian(ip->ip_len));
    //len = sizeof(struct tcp_pseudo_header) + tcpPseudoHeader->len;
    //lengh = ntohs(ip->ip_len) - (ipSize + tcpSize);

    printf("\n\tTCP Header\n");
    printTCPSourcePorts(tcp);
    printTCPDestPorts(tcp);
    printf("\t\tSequence Number: %u\n", htonl(tcp->tcp_seq));
    printf("\t\tACK Number: %u\n", htonl(tcp->tcp_ack));
    tcpPrintFlags(tcp);
    printf("\t\tWindow Size: %u\n", endian(tcp->tcp_window_size));
    tcpCheckSumRead(tcp, ip, tcpPseudoHeader, len);
}

void udpRead(const unsigned char *packet) {
    struct sniff_udp * udp = (struct sniff_udp *)
            (packet +  sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
    printf("\n\tUDP Header\n");
    printf("\t\tSource Port:  %u\n", endian(udp->udp_source));
    printf("\t\tDest Port:  %u\n", endian(udp->udp_dest));

}

void packetDistribute(const unsigned char *packet, struct pcap_pkthdr header) {
    ethernetRead(packet, header);
}

int main(int argc, char **argv) {
    pcap_t *pcapFile;
    int counter = 1;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;


    if((pcapFile = pcap_open_offline(argv[1], errbuf)) == NULL) {
        printf("pcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    while((packet = pcap_next(pcapFile, &header)) != NULL) {
        printf("\nPacket number: %i  Packet Len: %i\n\n", counter++, header.len);
        packetDistribute(packet, header);
    };

    pcap_close(pcapFile);
    return 0;
}

