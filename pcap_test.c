#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void packet_analysis(const u_char *packet)
{
	struct libnet_ethernet_hdr *ethhdr;
	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	unsigned short ether_type;
	unsigned short ip_type; 
	char buf1[20];
	char buf2[20];   
	int chcnt =0;
	int length;

	ethhdr = (struct libnet_ethernet_hdr *)packet;
	packet += sizeof(struct libnet_ethernet_hdr);

	printf("< Ethernet header >\n\n");
	printf("ethernet Src Mac  : %s\n",(char*)ether_ntoa(ethhdr->ether_shost));
	printf("ethernet Dst Mac  : %s\n\n",(char*)ether_ntoa(ethhdr->ether_dhost));	

	ether_type = ntohs(ethhdr->ether_type); 

	if (ether_type == ETHERTYPE_IP) 
	{	
		length = iphdr->ip_len;
		iphdr = (struct libnet_ipv4_hdr *)packet;
		
		printf("< IP Packet >\n\n");
		
		inet_ntop(AF_INET, &iphdr->ip_src, buf1, sizeof(buf1));
		printf("Src IP  : %s\n", buf1);
		inet_ntop(AF_INET, &iphdr->ip_dst, buf2, sizeof(buf2)); 
		printf("Dst IP  : %s\n\n", buf2);
	}
	else
	{
		printf("< No IP_Packet > \n\n");
		printf("-----------------------------------------------\n\n");
		return;
	}

	ip_type = iphdr->ip_p;

	if(ip_type == IPPROTO_TCP)
	{
		packet += iphdr->ip_hl * 4; 
		tcphdr = (struct libnet_tcp_hdr *)(packet); 
		printf("< TCP Packet >\n\n");
		printf("Src Port : %d\n" , ntohs(tcphdr->th_sport));
		printf("Dst Port : %d\n\n" , ntohs(tcphdr->th_dport));

		packet += tcphdr->th_off * 4;
		length = length - iphdr->ip_hl*4 - tcphdr->th_off*4;   

		printf("< DATA >\n\n");    
		while(length--)
		{
			printf("%02x", *(packet++)); 
			if ((++chcnt % 16) == 0) 
				printf("\n");
		}
		printf("\n\n");
		printf("-----------------------------------------------\n\n");
	}
	else
	{
		printf("< No TCP_Packet >\n\n");
		printf("-----------------------------------------------\n\n");
		return;
	}	

}

int main(int argc, char **argv)
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcd;  // packet capture descriptor
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res = 0;
		
	dev = argv[1];

	if (argc == 1)
	{
		printf("please select the dev\n");
		exit(1);
	}

	pcd = pcap_open_live(dev, BUFSIZ, 1/*PROMISCUOUS*/, -1, errbuf);

	if (pcd == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}    
	while(1)
	{

		res = pcap_next_ex(pcd, &header, &packet);
		if(res > 0)
			packet_analysis(packet);
		else
			continue;
	}
}
