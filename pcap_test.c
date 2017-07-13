#include "pcap_test.h"
#include <stdio.h>
void printEtherAddress(struct ether_header eh)
{
	printf("Destination MAC Address : ");
	for(int i = 0 ; i < 6 ; i ++)
		printf("%02x%c", eh.ether_dhost.ether_addr_octet[i], (i == 5) ? '\n' : ':');
	printf("Source MAC Address : ");
	for(int i = 0 ; i < 6 ; i ++)
		printf("%02x%c", eh.ether_shost.ether_addr_octet[i], (i == 5) ? '\n' : ':');
}

void printIpAddress(struct ip_header ip)
{
	printf("Destinsation IP Address : ");
	for(int i = 0 ; i < 4 ; i ++)
		printf("%d%c", ip.ip_destaddr.ip_addr_octet[i], (i == 3) ? '\n' : '.');
	printf("Source IP Address : ");
	for(int i = 0 ; i < 4 ; i ++)
		printf("%d%c", ip.ip_srcaddr.ip_addr_octet[i], (i == 3) ? '\n' : '.');
} 
void printTcpAddressAndData(struct tcp_header tcp)
{
	printf("Destination Port : %d\nSource Port : %d\n", tcp.tcp_destport,
									 tcp.tcp_srcport);
	for(int i = 0 ; i < 100 ; i ++) // print data. \n when 16, 32, 48... ,  99
		printf("%02x%c%c", tcp.tcp_data[i], ((i+1) % 16 == 0) ? '\n' : ' ', (i==99) ? '\n' : '\0');
}
