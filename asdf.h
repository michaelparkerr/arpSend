#include <stdio.h>  /* Standard I/O */
#include <stdlib.h> /* Standard Library */
#include <string.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <errno.h> /* Error number and related */
#define ENUMS
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <features.h> /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> /* The L2 protocols */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <pcap.h>

#define ARP 0x0806
#define MACADDRESSLENGTH 6

typedef struct _ethernetHeader
{
	u_int8_t ethernetDestinationMacAddress[MACADDRESSLENGTH]
	u_int8_t ethernetSourceMacAddress[MACADDRESSLENGTH];
	u_int16_t ethernetType;       			/* ARP : 0x0806, RARP : 0x0835 */
} ethernetHeader;

#pragma pack(push, 1)						/* remove struct padding */
typedef struct _arpHeader
{
	u_int16_t arpHardwareAddressType;
	u_int16_t arpProtocolAddressType;
	u_int8_t arpHardwareAddressLength;
	u_int8_t arpProtocolAddressLength;
	u_int16_t arpOperation;            			/* Request : 0x01, Reply : 0x02, RARP request : 0x03, RARP Replay : 0x04 */
	u_int8_t arpSourceMacAddress[MACADDRESSLENGTH];
	u_int32_t arpSourceIPAddress;
	u_int8_t arpDestinationMacAddress[MACADDRESSLENGTH];
	u_int32_t arpDestinationIPAddress;
} arpHeader;


int GetLocalMac(const char* dev, unsigned char* mac);
u_int32_t GetLocalIp(const char* dev);
void IpCharToUnint(const char* charIp, u_int32_t* intIp);

ethernetHeader* GenerateEthernetHeader(u_int8_t* ethernetDestinationMacAddress, u_int8_t* ethernetSourceMacAddress, u_int16_t ethernetType);
arpHeader* GenerateArpHeader(u_int16_t arpHardwareAddressType, u_int16_t arpProtocolAddressType, u_int8_t arpHardwareAddressLength, u_int8_t arpProtocolAddressLength, u_int16_t arpOperation, u_int8_t* arpSourceMacAddress, u_int32_t arpSourceIPAddress, u_int8_t* arpDestinationMacAddress, u_int32_t arpDestinationIPAddress);
void htonEthernet(ethernetHeader* ethernetHost);
void htonArp(arpHeader* arpHost);

u_int8_t* reverseArray(u_int8_t* uintArray);

int receiveReply(pcap_t* handle, u_int32_t arpSourceIPAddress, u_int8_t* ethernetSourceMacAddress);
int receiveRequest(pcap_t* handle, u_int32_t arpSourceIPAddress);
void sendPacket(pcap_t* handle, ethernetHeader* ethernetHost, arpHeader* arpHost);
void printPacket(ethernetHeader* ethernetHost, arpHeader* arpHost);
