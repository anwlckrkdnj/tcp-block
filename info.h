#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct PktInfo final {
	Mac smac_;
	Mac dmac_;
	Ip sip_;
	Ip dip_;
	uint8_t	ttl_;
	uint16_t sport_;
	uint16_t dport_;
	uint32_t seq_;
	uint32_t ack_;
	uint32_t length;

	Mac smac()	{ return smac_; }
	Mac dmac()	{ return dmac_;	}
	Ip sip()	{ return ntohl(sip_); }
	Ip dip()	{ return ntohl(dip_); }
	uint8_t ttl()	{ return ttl_; }
	uint16_t sport()	{ return ntohs(sport_); }
	uint16_t dport()	{ return ntohs(dport_); }
	uint32_t seq()	{ return seq_; }
	uint32_t ack()	{ return ack_; }
};
#pragma pack(pop)
