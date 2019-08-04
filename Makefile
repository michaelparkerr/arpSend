all : arpSend

arpSend: arpSend.o
	g++ -g -o arpSend arpSend.o -lpcap

arpSend.o:
	g++ -g -c -o arpSend.o arpSend.cpp 

clear:
	rm -f arpSend
	rm -f *.o
