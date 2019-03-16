#include <pcap.h>
#include <stdlib.h> /* malloc() */
#include <arpa/inet.h> /* inet_ntoa() */
#include <ctype.h> /* isprint() */
#include <netinet/in.h>
#include <string.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct EthernetHeader {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct IPHeader {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct TCPHeader {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        unsigned int th_seq;		/* sequence number */
        unsigned int th_ack;		/* acknowledgement number */

        u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
};

/* UDP Header */
struct UDPHeader
{
        unsigned short source;			// Source port
        unsigned short dest;			// Destination port
        unsigned short length;			// Packet length
        unsigned short checksum;		// Packet checksum
};

/* ICMP Header*/
struct ICMPHeader
{

        unsigned char  type;			// Type of ICMP packet
        unsigned char  subcode;			// Subcode of type of packet
        unsigned short checksum;		// Packet checksum
        unsigned short id;				// ID number
        unsigned short seq;				// Sequence number

};

// Flags of interested packets
bool catchTCP, catchUDP, catchICMP;

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
                if (isprint(*ch) && (*ch != 0x0a))
			printf("%c", *ch);
                else
                        printf(".");
                ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/* Packet analysis */
void packet_handler(u_char *args,
                    const struct pcap_pkthdr* pkthdr,
                    const u_char* packet
                    )
{
    #define SIZE_ETHERNET 14

    const struct EthernetHeader *ethernet; /* The ethernet header */
    const struct IPHeader *ip; /* The IP header */

    char *fromaddr, *toaddr;
    int fromport, toport;

    u_int size_ip;
    u_int size_tcp;
    ethernet = (struct EthernetHeader*)(packet);
    ip = (struct IPHeader*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
            printf("IP: Invalid header length: %u bytes\n", size_ip);
            return;
    }

    fromaddr = strdup(inet_ntoa(ip->ip_src));
    toaddr = strdup(inet_ntoa(ip->ip_dst));

    if ((ip->ip_p == IPPROTO_TCP) && catchTCP)
    {
        const struct TCPHeader *tcp;
        tcp = (struct TCPHeader*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("TCP: Invalid header length: %u bytes\n", size_tcp);
            return;
        }

        fromport = ntohs(tcp->th_sport);
        toport = ntohs(tcp->th_dport);
        printf("TCP: from %s:%d to %s:%d %d bytes\n", fromaddr, fromport, toaddr, toport, (pkthdr->len - SIZE_ETHERNET - size_ip));

        print_payload((const u_char *)(tcp + 20), (pkthdr->len - SIZE_ETHERNET - size_ip - 20));
    }

    else if ((ip->ip_p == IPPROTO_UDP) && catchUDP)
    {
        const struct UDPHeader *udp = (struct UDPHeader *)(packet + SIZE_ETHERNET + size_ip);
        // TODO: check packet validity
        fromport = htons(udp->source);
        toport = htons(udp->dest);

        printf( "UDP: from %s:%d to %s:%d %d bytes\n", fromaddr, fromport, toaddr, toport, (pkthdr->len - SIZE_ETHERNET - size_ip));

        print_payload((const u_char *)(udp + 8), (pkthdr->len - SIZE_ETHERNET - size_ip - 8));
    }

   else if ((ip->ip_p == IPPROTO_ICMP) && catchICMP)
    {
        const struct ICMPHeader *icmp = (struct ICMPHeader *)(packet + SIZE_ETHERNET + size_ip);
        // TODO: check packet validity
        printf("ICMP: from %s to %s %d bytes\n", fromaddr, toaddr, strlen((char *)icmp));
        if((icmp->type == 8) && (icmp->subcode == 0))
            printf("   ECHO REQUEST\n");
        if((icmp->type == 0) && (icmp->subcode == 0))
            printf("   ECHO REPLY\n");
    }

   free(fromaddr);
   free(toaddr);
}

int main(int argc,char **argv)
{
    char *dev;  // dev name
    pcap_t* descr; // dev desc
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp; // ip addr
    bpf_u_int32 maskp; // net mask
    char *filter = 0; // packet filter rule
    int promisc = 0; // promisc mode flag

    /* parse args */
    catchTCP = catchUDP = catchICMP = true;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--no-tcp") == 0)
            catchTCP = false;
        else if (strcmp(argv[i], "--no-udp") == 0)
            catchUDP = false;
        else if (strcmp(argv[i], "--no-icmp") == 0)
            catchICMP = false;
        else if (strcmp(argv[i], "--promisc") == 0)
            promisc = 1;
        else
            filter = strdup(argv[i]);
    }
    /* get dev name */
    // dev = "eth0";
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        return 0;
    }
    /* get iface info */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device  */
    descr = pcap_open_live(dev,BUFSIZ,promisc,-1,errbuf);
    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        return 0;
    }

    /* apply packet filter */
    if (argv[1]){
        struct bpf_program fp;
        if(pcap_compile(descr,&fp,filter,0,netp) == -1)
        {
            printf("Error calling pcap_compile: %s\n",filter);
            return 0;
        }
        if(pcap_setfilter(descr,&fp) == -1)
        {
            printf("Error setting filter\n");
            return 0;
        }
    }

    /* start packet capture */
    pcap_loop(descr,-1,packet_handler,NULL);

    return 0;
}
