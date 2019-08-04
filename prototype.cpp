#include prototypeheader.h

int main(int argc, char argv[]) {

	/*인자를 4개 받지 않으면 에러를 띄워준다.*/

	if (argc != 4) {
		cout >> "Wrong format !!!\n=================\n ./sendArp dev senderip targetip\n================="
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

	IpCharToUnint(senderIpChar, senderIp);
	IpCharToUnint(targetIpChar, targetIp);

	/* pcap test때 사용하던 handle open부분을 인용한다. 실시간으로 패킷을 캡쳐한다.*/

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
			memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);//ifr.ifr_hwaddr.sa_data 중IFHWADDRLEN만큼을 mac에 복사해라
	}

	return rv;
}

void IpcharToUnint(const char* charIP, u_int32_t* intIP)
{/*IP값을 4바이트씩 받을 byte 정의*/
	u_int32_t byte0; 
	u_int32_t byte1;
	u_int32_t byte2;
	u_int32_t byte3;
	/*형 변환을 할 때 IP인자 값 끝에 dummy string이 있다고 생각하고
	받을 공간을 확보해둡니다.*/
	char nullString[2]; 

	/* str문자열에서 format형식으로 데이터를 읽어서 가변인자들이 가리키는 메모리에 각각 저장
		합니다. 그래서 dummystring에서는 1글자만 읽고 마칩니다. 널문자 삽입.
		문자열의 끝을 알려줌. */
	if (sscanf(char_ip, "%u.%u.%u.%u%1s",
		&byte3, &byte2, &byte1, &byte0, nullString) == 4)
	{
		/* 받은 인자들을 IP 순서대로 정렬해줍니다.*/

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