#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "detect.h"
#include "forward.h"
#include "backward.h"
#include "info.h"
#include "mac.h"
#include "ip.h"
#include "mymac.h"

static pcap_t* handle;

void printMac(Mac mac) {
	uint8_t a[6];
	memcpy(a, &mac, sizeof(Mac));
	for(int i = 0 ; i < 6 ; i++) {
		printf("%02x", a[i]);
		if(i < 5)
			printf(":");
	}
}

void printIp(Ip ip) {
	int a;
	memcpy(&a, &ip, sizeof(Ip));
	printf("%d.%d.%d.%d", ((a&0xff)), ((a&0xff00)>>8), ((a&0xff0000)>>16), ((a&0xff000000)>>24));
}

void usage() {
	printf("> wrong format!\n");
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool checkFormat(int argc, char* argv[]) {
	printf("checking input format...\n");
	if (argc != 3)
		return false;
	printf("> done!\n\n");
	return true;
}

int main(int argc, char* argv[]) {
	if (checkFormat(argc, argv) == false) {
		usage();
		return -1;
	}

	Mac mymac;
	printf("gaining my mac address...\n");
	if (getMyMac(&mymac) == false) {
		printf("> cant get my mac address\n");
		return false;
	
	}
	printf("> done!\n\n");

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	u_char* relayPacket;
	int res;

	printf("detecting patterns...\n");
	while (true) {
		PktInfo pktinfo;

		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(0);
		}

		if (detectPattern(packet, header->caplen, argv[2], strlen(argv[2]), &pktinfo) == true) {
			printf("> detected!\n");
			sendForward(handle, &pktinfo, &mymac);
			sendBackward(handle, &pktinfo, &mymac);
		}
	}

	return 0;
}
