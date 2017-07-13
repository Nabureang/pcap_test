pcap_test : main.o pcap_test.o
	gcc -o pcap_test main.o pcap_test.o -lpcap

main.o : main.c
	gcc -c -o main.o main.c
pcap_test.o : pcap_test.c
	gcc -c -o pcap_test.o pcap_test.c

clean :
	rm *.o pcap_test
