#include "pcap_test.h"

void printEtherAddress(struct sniff_ethernet *eh)
{
	printf("Destination MAC Address : ");
	for(int i = 0 ; i < 6 ; i ++)
		printf("%02x%c", eh->ether_dhost[i], (i == 5) ? '\n' : ':');
	printf("Source MAC Address : ");
	for(int i = 0 ; i < 6 ; i ++)
		printf("%02x%c", eh->ether_shost[i], (i == 5) ? '\n' : ':');
}

void printIpAddress(struct sniff_ip *ih)
{
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ih->ip_dst), str, INET_ADDRSTRLEN);
	printf("Destinsation IP Address : %s\n", str );
	inet_ntop(AF_INET, &(ih->ip_src), str, INET_ADDRSTRLEN);
	printf("Source IP Address : %s\n", str );
} 

void printTcpAddress(struct sniff_tcp *th)
{
	printf("Destination Port : %d\nSource Port : %d\n", ntohs(th->th_dport),
							 ntohs(th->th_sport));
}

void printData(u_char *data, uint16_t length)
{
	int packet_num_line = 0;
	u_char *tmp = data;
	for(int i = 0 ; i < length ; i ++)
	{
		
		packet_num_line ++;

		printf("%02x ", *(data+i));
		
		if((i+1) % 16 == 0) // print data in char type
		{
			putchar('|');
			for(int j = 0 ; j < packet_num_line ; j ++)
			{ 	
				if(*(tmp+j) == 0x0d || *(tmp+j) == 0x0a  )
					putchar('.');
				else
					printf("%0c", *(tmp+j));
			}
			putchar('\n');
			tmp = data+i+1;
			packet_num_line = 0;
		}
	}
	if(packet_num_line != 0) // print extra last line data in char type
	{
		for(int k = 0 ; k < 16-packet_num_line ; k++)
		{
			printf("   ");
		} 
		putchar('|');
		for(int j = 0 ; j < packet_num_line ; j ++)
		{ 	
			if(*(tmp+j) == 0x0d || *(tmp+j) == 0x0a  )
				putchar('.');
			else
				printf("%0c", *(tmp+j));
		}
		putchar('\n');
	}
		
}
	
