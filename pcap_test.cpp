//BoB 6th BadSpell(KJS)
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <ctype.h>

typedef struct _PACKET_INFO
{
	unsigned char destmac[6]; //0x00
	unsigned char sourcemac[6]; //0x06
	short iptype; //0x0C
	char version; //0x0E
	char dscp; //0x0F
	short totalLength; //0x10
	short id; //0x12
	short flag; //0x14
	char ttl; //0x16
	char protocol; //0x17
	short headerchecksum; //0x18
	int sourceip; //0x1A
	int destip; //0x1E
	short sourceport; //0x22
	short destport; //0x24
	char unknown[0x10]; //0x34
	unsigned char data[65536]; //0x36
} __attribute__((packed)) PACKET_INFO, *LPPACKET_INFO;

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
	unsigned char *ip = (unsigned char *)&_ip;
	sprintf(ipAddress, "%d.%d.%d.%d", ip[0], ip[1],  ip[2],  ip[3]);
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
		LPPACKET_INFO packetInfo = (LPPACKET_INFO)packet;

		printf("Source MAC: %s / IP: %s:%d\n", getMac(packetInfo->sourcemac), getIP(packetInfo->sourceip), ntohs(packetInfo->sourceport));
		printf("Destin MAC: %s / IP: %s:%d\n", getMac(packetInfo->destmac), getIP(packetInfo->destip), ntohs(packetInfo->destport));
		printf("--------------------------- DATA START ---------------------------\n");
		for (int j = 0; j < 3; j++)
		{
			printf("%04X  ", j * 0x10);
			for (int i = 0; i < 0x10; i++)
				printf("%02X ", packetInfo->data[i + j * 0x10]);
			printf(" ");
			for (int i = 0; i < 0x10; i++)
			{
				char c = packetInfo->data[i + j * 0x10];
				printf("%c", isprint(c) ? c : '.');
			}
			printf("\n");
		}
		printf("---------------------------- DATA END ----------------------------\n\n\n");
	}
	pcap_close(handle);
	return 0;
}