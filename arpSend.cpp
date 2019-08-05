#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>

/* 다른 사람이 짜둔 GetLocalMac, 각각 라인에 대해 따로 주석을 달아 두었다.*/
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