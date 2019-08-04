#include prototypeheader.h

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
	printPacket(ethernetHost, arpHost]);
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