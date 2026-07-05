#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_VLAN 0x8100
#define HTTP_PREVIEW_LIMIT 2048

struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct vlanheader
{
    u_short tci;
    u_short ether_type;
};

struct ipheader
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char iph_ihl : 4, iph_ver : 4;
#else
    unsigned char iph_ver : 4, iph_ihl : 4;
#endif
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct tcpheader
{
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

static int packet_no = 0;

static void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_tcp_flags(u_char flags)
{
    int printed = 0;
    struct
    {
        u_char bit;
        const char *name;
    } flag_names[] = {
        {TH_SYN, "SYN"},
        {TH_ACK, "ACK"},
        {TH_FIN, "FIN"},
        {TH_RST, "RST"},
        {TH_PUSH, "PSH"},
        {TH_URG, "URG"},
        {TH_ECE, "ECE"},
        {TH_CWR, "CWR"},
    };

    for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++)
    {
        if (flags & flag_names[i].bit)
        {
            printf("%s%s", printed ? "," : "", flag_names[i].name);
            printed = 1;
        }
    }
    if (!printed)
    {
        printf("NONE");
    }
}

static const char *ip_to_string(struct in_addr addr, char *buf, size_t len)
{
    if (inet_ntop(AF_INET, &addr, buf, len) == NULL)
    {
        snprintf(buf, len, "invalid");
    }
    return buf;
}

static int is_http_like(const u_char *payload, int len)
{
    const char *methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "HTTP/"};

    if (len < 4)
    {
        return 0;
    }

    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        size_t method_len = strlen(methods[i]);
        if ((size_t)len >= method_len && memcmp(payload, methods[i], method_len) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static int contains_case_insensitive(const char *buf, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len == 0)
    {
        return 1;
    }

    for (const char *p = buf; *p; p++)
    {
        size_t i = 0;
        while (i < needle_len && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
        {
            i++;
        }
        if (i == needle_len)
        {
            return 1;
        }
    }

    return 0;
}

static void print_http_message(const u_char *payload, int payload_len)
{
    int preview_len = payload_len > HTTP_PREVIEW_LIMIT ? HTTP_PREVIEW_LIMIT : payload_len;
    char preview[HTTP_PREVIEW_LIMIT + 1];

    for (int i = 0; i < preview_len; i++)
    {
        preview[i] = (isprint(payload[i]) || payload[i] == '\r' ||
                      payload[i] == '\n' || payload[i] == '\t')
                         ? (char)payload[i]
                         : '.';
    }
    preview[preview_len] = '\0';

    printf("HTTP Message (%d bytes, preview %d bytes)\n", payload_len, preview_len);
    printf("----------------------------------------\n");
    printf("%s\n", preview);
    printf("----------------------------------------\n");

    if (contains_case_insensitive(preview, "Authorization:"))
    {
        printf("[Forensic Note] Authorization header detected. Plain HTTP can expose credentials.\n");
    }
    if (contains_case_insensitive(preview, "Cookie:"))
    {
        printf("[Forensic Note] Cookie header detected. Session data may be exposed on plaintext HTTP.\n");
    }
    if (contains_case_insensitive(preview, "password=") ||
        contains_case_insensitive(preview, "passwd=") ||
        contains_case_insensitive(preview, "token="))
    {
        printf("[Forensic Note] Credential-like parameter detected in HTTP payload.\n");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    packet_no++;

    if (header->caplen < sizeof(struct ethheader))
    {
        printf("[Packet %d] Truncated Ethernet frame\n", packet_no);
        return;
    }

    const struct ethheader *eth = (const struct ethheader *)packet;
    uint16_t ether_type = ntohs(eth->ether_type);
    int ethernet_len = sizeof(struct ethheader);

    if (ether_type == ETHERTYPE_VLAN)
    {
        if (header->caplen < sizeof(struct ethheader) + sizeof(struct vlanheader))
        {
            printf("[Packet %d] Truncated VLAN frame\n", packet_no);
            return;
        }
        const struct vlanheader *vlan = (const struct vlanheader *)(packet + ethernet_len);
        ether_type = ntohs(vlan->ether_type);
        ethernet_len += sizeof(struct vlanheader);
    }

    if (ether_type != ETHERTYPE_IP)
    {
        return;
    }

    if (header->caplen < (bpf_u_int32)(ethernet_len + (int)sizeof(struct ipheader)))
    {
        printf("[Packet %d] Truncated IP header\n", packet_no);
        return;
    }

    const struct ipheader *ip = (const struct ipheader *)(packet + ethernet_len);
    int ip_header_len = ip->iph_ihl * 4;
    int ip_total_len = ntohs(ip->iph_len);

    if (ip->iph_ver != 4 || ip_header_len < 20)
    {
        printf("[Packet %d] Invalid IPv4 header\n", packet_no);
        return;
    }

    if (ip->iph_protocol != IPPROTO_TCP)
    {
        return;
    }

    if (ip_total_len < ip_header_len ||
        header->caplen < (bpf_u_int32)(ethernet_len + ip_total_len))
    {
        printf("[Packet %d] Truncated IPv4 packet\n", packet_no);
        return;
    }

    if (header->caplen < (bpf_u_int32)(ethernet_len + ip_header_len + (int)sizeof(struct tcpheader)))
    {
        printf("[Packet %d] Truncated TCP header\n", packet_no);
        return;
    }

    const struct tcpheader *tcp = (const struct tcpheader *)(packet + ethernet_len + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    if (tcp_header_len < 20 || ip_total_len < ip_header_len + tcp_header_len)
    {
        printf("[Packet %d] Invalid TCP header length\n", packet_no);
        return;
    }

    const u_char *payload = packet + ethernet_len + ip_header_len + tcp_header_len;
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    printf("\n================ Packet %d ================\n", packet_no);
    printf("Captured length: %u bytes, Original length: %u bytes\n",
           header->caplen, header->len);

    printf("Ethernet Header\n");
    printf("  MAC: ");
    print_mac(eth->ether_shost);
    printf(" / ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("IP Header\n");
    printf("  IP: %s / %s\n",
           ip_to_string(ip->iph_sourceip, src_ip, sizeof(src_ip)),
           ip_to_string(ip->iph_destip, dst_ip, sizeof(dst_ip)));
    printf("  IP Header Length: %d bytes | IP Total Length : %d bytes | TTL: %u\n", ip_header_len, ip_total_len, ip->iph_ttl);

    printf("TCP Header\n");
    printf("  Port: %u / %u\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));
    printf("  TCP Header Length: %d bytes\n", tcp_header_len);
    printf("  Flags: ");
    print_tcp_flags(tcp->tcp_flags);
    printf("\n");

    if ((tcp->tcp_flags & TH_SYN) && !(tcp->tcp_flags & TH_ACK))
    {
        printf("[Note] SYN without ACK. This may be a connection attempt or scan indicator.\n");
    }
    if (tcp->tcp_flags & TH_RST)
    {
        printf("[Note] RST observed. This can appear in rejected connections or scan responses.\n");
    }

    if (payload_len > 0)
    {
        if (is_http_like(payload, payload_len))
        {
            print_http_message(payload, payload_len);
        }
        else
        {
            printf("Application Data: %d bytes, not recognized as plaintext HTTP\n", payload_len);
        }
    }
    else
    {
        printf("Application Data: none\n");
    }
}

static void usage(const char *prog)
{
    printf("Usage:\n");
    printf("  Live capture: %s <interface> [bpf-filter]\n", prog);
    printf("\nExamples:\n");
    printf("  sudo %s enp0s3 \"tcp port 80\"\n", prog);
    printf("  sudo %s en0 \"tcp\"\n", prog);
}

int main(int argc, char *argv[])
{
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    const char *filter_exp = "tcp";
    const char *dev = NULL;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
    char net_str[INET_ADDRSTRLEN];
    char mask_str[INET_ADDRSTRLEN];

    if (argc < 2)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    dev = argv[1];

    if (argc >= 3)
    {
        filter_exp = argv[2];
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Could not get netmask for %s: %s\n", dev, errbuf);
        fprintf(stderr, "Continue with PCAP_NETMASK_UNKNOWN.\n");
        net = 0;
        mask = PCAP_NETMASK_UNKNOWN;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Could not open source: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1)
    {
        pcap_perror(handle, "pcap_compile error");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "pcap_setfilter error");
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("Interface: %s\n", dev);
    printf("Network: %s\n", ip_to_string(*(struct in_addr *)&net, net_str, sizeof(net_str)));
    printf("Netmask: %s\n", ip_to_string(*(struct in_addr *)&mask, mask_str, sizeof(mask_str)));
    printf("Filter: %s\n", filter_exp);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return EXIT_SUCCESS;
}
