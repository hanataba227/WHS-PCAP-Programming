#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

// Ethernet header
struct ethheader
{
    u_char ether_dhost[6]; // destination host address
    u_char ether_shost[6]; // source host address
    u_short ether_type;    // protocol type (IP, ARP, RARP, etc)
};

// IP Header
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
  };

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet; // ethernet header structure
    
    if (ntohs(eth->ether_type) == 0x0800)               // ipv4 일때
    {
        // mac 주소
        printf("src mac : %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
        printf("dst mac : %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
        printf("\n");

        // ip 헤더
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ipheader_len = ip->iph_ihl * 4;
        printf("src ip: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("dst ip: %s\n", inet_ntoa(ip->iph_destip));
        printf("\n");

        // tcp 헤더
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ipheader_len);
        int tcpheader_len = tcp->tcp_offx2 * 4;
        printf("src port: %d\n", ntohs(tcp->tcp_sport));
        printf("dst port: %d\n", ntohs(tcp->tcp_dport));
        printf("\n");


        if (ntohs(ip->iph_len) - ip_header_len - tcpheader_len > 0)
        {
            unsigned char *data = (unsigned char *)(packet + sizeof(struct ethheader) + ipheader_len + tcpheader_len);
            for (int i = 0; i < ip->iph_len - ipheader_len - tcpheader_len - sizeof(struct ethheader) && i < 300; i++)
            {
                if (i % 10 == 0)
                {
                    printf("\n");
                }

                printf("%02X ", data[i]);
            }
            printf("\n");
        }
        printf("\n");
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    
    return 0;
}
