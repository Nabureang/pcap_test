struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct ether_addr ether_dhost;
	struct ether_addr ether_shost;
	unsigned ether_type;
};
struct ip_addr
{
	unsigned char ip_addr_octet[4];
};
struct ip_header
{
	unsigned char temp[12];  //We need only srcaddr, destaddr. so SKIP
	struct ip_addr ip_srcaddr;
	struct ip_addr ip_destaddr;
};
struct tcp_header
{
	unsigned short tcp_srcport;
	unsigned short tcp_destport;
	unsigned char temp[20];  //We do not need these information
	unsigned char tcp_data[100]; // data by 100byte
}; 
