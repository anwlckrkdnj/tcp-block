#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include "info.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include "calc.h"

#pragma pack(push, 1)
struct ForwardFormat {
	EthHdr eth_;
	struct libnet_ipv4_hdr ipv4_;
	struct libnet_tcp_hdr tcp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct PseudoHdr {
	Ip sip;
	Ip dip;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t length;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TCPBuff1 {
	struct PseudoHdr pseudohdr;
	struct libnet_tcp_hdr tcp_;
} TCPbuff1;
#pragma pack(pop)

void sendForward(pcap_t* handle, PktInfo* pktinfo, Mac* mymac) {
	struct ForwardFormat packet;

	packet.eth_.smac_ = *mymac;
	packet.eth_.dmac_ = pktinfo->dmac();
	packet.eth_.type_ = htons(EthHdr::Ip4);
	
	packet.ipv4_.ip_v = (uint8_t) 4;
	packet.ipv4_.ip_hl = (uint8_t) (sizeof(packet.ipv4_) >> 2);
	packet.ipv4_.ip_tos = (uint8_t) 0;
	packet.ipv4_.ip_len = ntohs(sizeof(packet.ipv4_) + sizeof(packet.tcp_));
	packet.ipv4_.ip_id = 0;
	packet.ipv4_.ip_off = (uint16_t) 0;
	packet.ipv4_.ip_ttl = pktinfo->ttl();
	packet.ipv4_.ip_p = (uint8_t) 6;
	packet.ipv4_.ip_src.s_addr = pktinfo->sip();
	packet.ipv4_.ip_dst.s_addr = pktinfo->dip();
	packet.ipv4_.ip_sum = 0;

	packet.tcp_.th_sport = pktinfo->sport();
	packet.tcp_.th_dport = pktinfo->dport();
	packet.tcp_.th_seq = ntohl(pktinfo->seq() + pktinfo->length);
	packet.tcp_.th_ack = ntohl(pktinfo->ack());
	packet.tcp_.th_flags = (uint16_t) 0x014;
	packet.tcp_.th_off = (uint8_t) sizeof(packet.tcp_) >> 2;
	packet.tcp_.th_win = (uint16_t) 0xfffe;
	packet.tcp_.th_urp = (uint16_t) 0;
	packet.tcp_.th_sum = 0;

	packet.ipv4_.ip_sum = ntohs(ip_sum_calc(20, (char*)(&packet) + 14));

	TCPbuff1.pseudohdr.sip = pktinfo->sip();
	TCPbuff1.pseudohdr.dip = pktinfo->dip();
	TCPbuff1.pseudohdr.reserved = (uint8_t) 0;
	TCPbuff1.pseudohdr.protocol = (uint8_t) 6;
	TCPbuff1.pseudohdr.length = (uint16_t) htons(20);
	memcpy(&TCPbuff1.tcp_, &packet.tcp_, 20);

	packet.tcp_.th_sum = tcp_sum_calc(sizeof(TCPbuff1), (u_short*)&TCPbuff1);

	pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(ForwardFormat));
}
