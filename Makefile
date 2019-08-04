all : sendArp

sendArp: main.o
	g++ -g -o sendArp main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp 

clear:
	rm -f sendArp
	rm -f *.o
