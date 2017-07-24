#include "pcap_test.h"
int main(int argc, char *argv[])
{		
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	uint32_t packet_ex;
	uint16_t packet_length;

	/* Define the device */	
	if(argc < 2)
	{
		printf("Please input network interface.\n");
		exit(-1);
	}
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	/* Print its length */
	while(1)
	{
		if(packet_ex = pcap_next_ex(handle, &header, &packet) >= 1)
		{
			struct sniff_ethernet *eh;
			struct sniff_ip *ih;
			struct sniff_tcp *th;					
			eh = (struct sniff_ethernet *)packet;
			if(ntohs(eh->ether_type) != ETHERTYPE_IP)
			{
				printf("This packet is not IP packet\n");
				exit(-1);
			}
			packet += 14; // +14 (ip)
			ih = (struct sniff_ip *)packet;
			if(ih->ip_p != IPPROTO_TCP)
			{
				printf("This packet is not TCP packet\n");
				exit(-1);
			}
			packet += (uint16_t)((ih->ip_vhl)&0x0F) * 4; // ip_header length
			th = (struct sniff_tcp *)packet;
			packet += (((th->th_offx2)& 0xf0) >> 4) * 4;
			packet_length = ntohs(ih->ip_len) - ((ih->ip_vhl)&0x0F) * 4 - (((th->th_offx2)& 0xf0) >> 4) * 4;
			printf("--------------------------------------------\n");
			printf("\ntotal_length : %d , ip_header_length : %d , tcp_header_length : %d\n", ntohs(ih->ip_len), ((ih->ip_vhl)&0x0F) * 4, (((th->th_offx2)& 0xf0) >> 4) * 4 );
			printEtherAddress(eh);
			printIpAddress(ih);
			printTcpAddress(th);
			printData(packet, packet_length);
		}
		else if(packet_ex == -1 && packet_ex == -2)
		{
			printf("Parsing Error : pcap_next_ex\n");
			exit(-1);
		}	
	}
	pcap_close(handle);
	return(0);
}
