//
// Created by Grant Campanelli on 4/8/15.
//

#ifndef PROGRAM1_TRACE_H
#define PROGRAM1_TRACE_H

#define endian(hex) (((hex & 0x00ff) << 8) + ((hex & 0xff00) >> 8))


#define ETHER_ADDR_LEN	6 /* Ethernet addresses are 6 bytes */
#define ARP_MAC_ADDR_LEN 6
#define ARP_IP_ADDR_LEN 4
#define ETHER_SIZE 14


/* Ethernet header */
struct sniff_ethernet {
    unsigned char eth_dest[ETHER_ADDR_LEN]; /* Destination host address */
    unsigned char eth_src[ETHER_ADDR_LEN]; /* Source host address */
    unsigned short eth_type; /* IP? ARP? RARP? etc */
};

struct sniff_arp {
    unsigned short arp_hardware;
    unsigned short arp_prot_type;
    unsigned char arp_hardware_size;
    unsigned char arp_prot_size;
    unsigned short arp_opcode;
    unsigned char arp_send_mac_addr[ARP_MAC_ADDR_LEN];
    unsigned char arp_send_ip_addr[ARP_IP_ADDR_LEN];
    unsigned char arp_targ_mac_addr[ARP_MAC_ADDR_LEN];
    unsigned char arp_targ_ip_addr[ARP_IP_ADDR_LEN];

};
/*
 * IP header info
 */
#define ARP_FLAG 1544
#define IP_FLAG 8
#define IP_IHL 0x0F
#define IP_ADDR_LENGTH 4
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_TCP 0x6
#define IP_UDP 0x11
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_ICMP 0x01		/* more fragments flag */
#define IP_ICMP_REQUEST 8
#define IP_ICMP_REPLY 0

/*
 * IP Struct
 */
struct sniff_ip {
    unsigned char ip_version;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_sum;
    unsigned char ip_source[IP_ADDR_LENGTH];
    unsigned char ip_dest[IP_ADDR_LENGTH];
};


/*
 * TCP/UDP Port Numbers
 */
#define FTP_P20 20
#define FTP_P21 21
#define SMTP 25
#define HTTP 80
#define POP3 110

/*
 * UDP Struct
 */
struct sniff_udp {
    unsigned short udp_source;
    unsigned short udp_dest;
};

/*
 * TCP Struct
 */
struct sniff_tcp {
    unsigned short tcp_src;
    unsigned short tcp_dest;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_offset;
    unsigned char tcp_flags;
    unsigned short tcp_window_size;
    unsigned short tcp_checksum;
    unsigned short tcp_urg_ptr;
};

/*
 *  TCP Flags
 */
#define TCP_SYN 2
#define TCP_RST 4
#define TCP_FIN 1

/*
 * Pseudo-header
 */
struct tcp_pseudo_header {
    unsigned char src[IP_ADDR_LENGTH];
    unsigned char dest[IP_ADDR_LENGTH];
    unsigned char pad;
    unsigned char protocol;
    unsigned short len;
};


/*
 * Function Definitions
 */
void printMacAddr(unsigned char * addr);
void printIPAddr(unsigned char * addr);
void arpRead(const unsigned char *packet);
void ethernetRead(const unsigned char *packet, struct pcap_pkthdr header);
void ipRead(const unsigned char *packet, struct pcap_pkthdr header);
void icmpRead(const unsigned char *packet, unsigned short ip_length);
void tcpRead(const unsigned char *packet, struct sniff_ip *ip, int length);
void udpRead(const unsigned char *packet);
void ipDistribute(const unsigned char *packet, int flag, struct sniff_ip *ip, int length);
void tcpCheckSumRead(struct sniff_tcp * tcp, struct tcp_pseudo_header header,
                     int length);
void printTCPSourcePorts(struct sniff_tcp *tcp);
void printTCPDestPorts(struct sniff_tcp *tcp);


#endif //PROGRAM1_TRACE_H
