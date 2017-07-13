#Makefile
all: pcap_test

pcap_test: pcap_test.o
	gcc -o pcap_test pcap_test.o -lpcap 

pcap_test.o: pcap_test.cpp
	gcc -c -o pcap_test.o pcap_test.cpp -lpcap

clean:
	rm -f pcap_test
	rm -f *.o