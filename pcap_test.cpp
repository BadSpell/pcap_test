//BoB 6th BadSpell(KJS)
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>

typedef struct _ETHER_INFO
{
	uint8_t destmac[6]; //0x00
	uint8_t sourcemac[6]; //0x06
	uint16_t iptype; //0x0C
} __attribute__((packed)) ETHER_INFO, *LPETHER_INFO;

typedef struct _IP_INFO
{
	uint8_t version; //0x0E
	uint8_t dscp; //0x0F
	uint16_t totalLength; //0x10
	uint16_t id; //0x12
	uint16_t flag; //0x14
	uint8_t ttl; //0x16
	uint8_t protocol; //0x17
	uint16_t headerchecksum; //0x18
	uint32_t sourceip; //0x1A
	uint32_t destip; //0x1E
}  __attribute__((packed)) IP_INFO, *LPIP_INFO;

typedef struct _TCP_HEADER
{
	uint16_t sourceport; //0x22
	uint16_t destport; //0x24
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t headerlen;
	uint8_t flag;
	uint16_t wnd;
	uint16_t checksum;
	uint16_t urgptr;
} __attribute__((packed)) TCP_HEADER, *LPTCP_HEADER;

char macAddress[32];
char *getMac(uint8_t *mac)
{
	sprintf(macAddress, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1],  mac[2],  mac[3],  mac[4], mac[5]);
	return macAddress;
}

char ipAddress[32];
char *getIP(int _ip)
{
	inet_ntop(AF_INET, &_ip, ipAddress, sizeof(ipAddress));
	return ipAddress;
}

int main(int argc, char **argv)
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;

	if (argc == 2)
		dev = argv[1]; // User's selected interfaces
	else
	{
		dev = pcap_lookupdev(errbuf);
		if (!dev)
		{
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return 2;
		}
	}
	printf("*** Selected network interfaces to %s ***\n", dev);
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	printf("Packet capturing...\n\n");
	while (pcap_next_ex(handle, &header, &packet) >= 0)
	{
		if (!packet) // Null packet check
			continue;

		LPETHER_INFO etherInfo = (LPETHER_INFO)packet;
		if (ntohs(etherInfo->iptype) != ETHERTYPE_IP) // Check if header contains IPv4
			continue;

		LPIP_INFO ipInfo = (LPIP_INFO)(packet + sizeof(ETHER_INFO));
		if (ipInfo->protocol != IPPROTO_TCP) // Check if TCP
			continue;

		LPTCP_HEADER tcpInfo = (LPTCP_HEADER)(packet + sizeof(ETHER_INFO) + sizeof(IP_INFO));
		if (ntohs(tcpInfo->sourceport) != 80 && ntohs(tcpInfo->destport) != 80) // Only HTTP port
			continue;
		
		uint8_t *tcpdata = (uint8_t *)(packet + sizeof(ETHER_INFO) + sizeof(IP_INFO) + (tcpInfo->headerlen >> 4) * 4);
		int szTcpdata = ntohs(ipInfo->totalLength) - sizeof(IP_INFO) - (tcpInfo->headerlen >> 4) * 4;

		printf("Source MAC: %s / IP: %s:%d\n", getMac(etherInfo->sourcemac), getIP(ipInfo->sourceip), ntohs(tcpInfo->sourceport));
		printf("Destin MAC: %s / IP: %s:%d\n", getMac(etherInfo->destmac), getIP(ipInfo->destip), ntohs(tcpInfo->destport));
		printf("DataSize: %d\n", szTcpdata);
		if (!szTcpdata) // Null Data
		{
			printf("\n");
			continue;
		}
		
		printf("------------------- DATA START (Max Show 0x40) -------------------\n");
		for (int j = 0; j < (szTcpdata / 0x10 + 1) && j < 4; j++)
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