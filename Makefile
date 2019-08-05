all :
	gcc -o arp_send arp_send.cpp -lpcap

clear:
	rm -f arp_send
	rm -f *.o
