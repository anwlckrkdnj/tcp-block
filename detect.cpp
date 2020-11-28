#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "bm.h"
#include "info.h"

int isIPPacket(const u_char* packet, PktInfo* pktinfo) {
	EthHdr* eth_ = (EthHdr*) packet;
	if (eth_->type_ != htons(eth_->Ip4))
		return -1;

	pktinfo->dmac_ = eth_->dmac();
	pktinfo->smac_ = eth_->smac();	
	return sizeof(EthHdr);
}

int isTCPPacket(const u_char* packet, int offset, PktInfo* pktinfo) {
	struct libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)(packet + offset);
	if (ipv4_hdr->ip_p != IPPROTO_TCP)
		return -1;
	pktinfo->ttl_ = ipv4_hdr->ip_ttl;
	pktinfo->dip_ = htonl(ipv4_hdr->ip_dst.s_addr);
	pktinfo->sip_ = htonl(ipv4_hdr->ip_src.s_addr);
	pktinfo->length = htons(ipv4_hdr->ip_len) - (ipv4_hdr->ip_hl << 2);
	return offset + (ipv4_hdr->ip_hl << 2);
}

int isTLSPacket(const u_char* packet, int offset, PktInfo* pktinfo) {
	struct libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)(packet + offset);	
	if (tcp_hdr->th_dport != htons(443))
		return -1;
	int tcp_hdr_len = tcp_hdr->th_off << 2;

	char* payload = (char*)(packet + offset + tcp_hdr_len);
	uint16_t tmp = 0;
	memcpy(&tmp, payload + 1, 2);
	if (tmp != htons(0x0301) && tmp != htons(0x0302) && tmp != htons(0x0303)) {
		return -1;
	}
	pktinfo->dport_ = htons(tcp_hdr->th_dport);
	pktinfo->sport_ = htons(tcp_hdr->th_sport);
	pktinfo->seq_ = htonl(tcp_hdr->th_seq);
	pktinfo->ack_ = htonl(tcp_hdr->th_ack);
	pktinfo->length -= tcp_hdr_len;
	return offset + tcp_hdr_len;
}

bool checkPattern(const u_char* packet, int packetLen, char* pattern, int patternLen, int offset) {
	uint8_t* pat = (uint8_t*) pattern;
	uint8_t* txt = (uint8_t*) packet + offset;
	BmCtx* ctx = BoyerMooreCtxInit(pat, (uint16_t)patternLen);
	uint8_t* found = BoyerMoore(pat, (uint16_t)patternLen, txt, (uint16_t)(packetLen - offset), ctx);
	BoyerMooreCtxDeInit(ctx);

	if (found == NULL)
		return false;

	return true;
}

bool detectPattern(const u_char* packet, int packetLen, char* pattern, int patternLen, PktInfo* pktinfo) {
	
	int ip_offset = isIPPacket(packet, pktinfo);
	if (ip_offset == -1)
		return false;

	int tcp_offset = isTCPPacket(packet, ip_offset, pktinfo);
	if (tcp_offset == -1)
		return false;

	int tls_offset = isTLSPacket(packet, tcp_offset, pktinfo);
	if (tls_offset == -1)
		return false;

	if (checkPattern(packet, packetLen, pattern, patternLen, tls_offset) == false)
		return false;

	return true;
}
