#pragma once

#include <stdio.h>
#include "info.h"
#include "pcap.h"
#include "mac.h"

void sendForward(pcap_t* handle, PktInfo* pktinfo, Mac* mymac);
