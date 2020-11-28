#pragma once

#include "pcap.h"
#include "info.h"
#include "mac.h"

void sendBackward(pcap_t* handle, PktInfo* pktinfo, Mac* mymac); 
