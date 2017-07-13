#Makefile
all: pcap_test

pcap_test: pcap_test.c
	gcc -o pcap_test pcap_test.c -lpcap

clean:
	rm -f pcap_test

