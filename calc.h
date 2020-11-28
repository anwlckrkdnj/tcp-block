#pragma once

#include <libnet.h>

u_short ip_sum_calc(u_short len_ip_header, char* IPbuff);
u_short tcp_sum_calc(int size, u_short *buffer);
