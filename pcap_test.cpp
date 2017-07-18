//BoB 6th BadSpell(KJS)
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

typedef struct _ETHER_INFO
{
	unsigned char destmac[6]; //0x00
	unsigned char sourcemac[6]; //0x06
	unsigned short iptype; //0x0C
} __attribute__((packed)) ETHER_INFO, *LPETHER_INFO;

typedef struct _IP_INFO
{
	char version; //0x0E
	char dscp; //0x0F
	unsigned short totalLength; //0x10
	unsigned short id; //0x12
	unsigned short flag; //0x14
	char ttl; //0x16
	char protocol; //0x17
	unsigned short headerchecksum; //0x18
	int sourceip; //0x1A
	int destip; //0x1E
}  __attribute__((packed)) IP_INFO, *LPIP_INFO;

typedef struct _TCP_HEADER
{
	unsigned short sourceport; //0x22
	unsigned short destport; //0x24
	unsigned int seqnum;
	unsigned int acknum;
	unsigned char headerlen;
	unsigned char flag;
	unsigned short wnd;
	unsigned short checksum;
	unsigned short urgptr;
} __attribute__((packed)) TCP_HEADER, *LPTCP_HEADER;

char macAddress[32];
char *getMac(unsigned char *mac)
{
	sprintf(macAddress, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1],  mac[2],  mac[3],  mac[4], mac[5]);
	return macAddress;
}

char ipAddress[32];
char *getIP(int _ip)
{
	inet_ntop(AF_INET, &_ip, ipAddress, sizeof(ipAddress));

	//unsigned char *ip = (unsigned char *)&_ip;
	//sprintf(ipAddress, "%d.%d.%d.%d", ip[0], ip[1],  ip[2],  ip[3]);
	return ipAddress;
}

int main()
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "";
	bpf_u_int32 mask;	
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if (!packet)
			continue;

		LPETHER_INFO etherInfo = (LPETHER_INFO)packet;

		// Check if header contains IPv4
		if (ntohs(etherInfo->iptype) != 0x0800)
			continue;

		LPIP_INFO ipInfo = (LPIP_INFO)(packet + sizeof(ETHER_INFO));

		if (ipInfo->protocol != 6) // Check if TCP
			continue;

		LPTCP_HEADER tcpInfo = (LPTCP_HEADER)(packet + sizeof(ETHER_INFO) + sizeof(IP_INFO));
		if (ntohs(tcpInfo->sourceport) != 80) //Only HTTP Port
			continue;
		
		unsigned char *tcpdata = (unsigned char *)(packet + sizeof(ETHER_INFO) + sizeof(IP_INFO) + (tcpInfo->headerlen >> 4) * 4);
		int szTcpdata = ntohs(ipInfo->totalLength) - sizeof(IP_INFO) - (tcpInfo->headerlen >> 4) * 4;

		printf("Source MAC: %s / IP: %s:%d\n", getMac(etherInfo->sourcemac), getIP(ipInfo->sourceip), ntohs(tcpInfo->sourceport));
		printf("Destin MAC: %s / IP: %s:%d\n", getMac(etherInfo->destmac), getIP(ipInfo->destip), ntohs(tcpInfo->destport));
		printf("DataSize: %d\n", szTcpdata);
		printf("--------------------------- DATA START ---------------------------\n");
		for (int j = 0; j < szTcpdata / 0x10 && j < 3; j++)
		{
			printf("%04X  ", j * 0x10);
			for (int i = 0; i < 0x10; i++)
				printf("%02X ", tcpdata[i + j * 0x10]);
			printf(" ");
			for (int i = 0; i < 0x10; i++)
			{
				char c = tcpdata[i + j * 0x10];
				printf("%c", isprint(c) ? c : '.');
			}
			printf("\n");
		}
		printf("---------------------------- DATA END ----------------------------\n\n\n");
	}
	pcap_close(handle);
	return 0;
}