#pragma once

#include <stdio.h>
#include <pcap.h>
#include "info.h"

bool detectPattern(const u_char* packet, int packetLen, char* pattern, int patternLen, PktInfo* pktinfo);
