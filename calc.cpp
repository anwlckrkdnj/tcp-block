#include <libnet.h>

u_short ip_sum_calc(u_short len_ip_header, char* IPbuff) {
        u_short word16;
        u_int sum = 0;
        u_short i;

        for(i = 0; i < len_ip_header; i = i + 2) {
                word16 = ((IPbuff[i] << 8) & 0xFF00) + (IPbuff[i+1] & 0xFF);
                sum = sum + (u_int) word16;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        sum = ~sum;

        return ((u_short) sum);
}

u_short tcp_sum_calc(int size, u_short *buffer) {
        unsigned long cksum=0;
        while(size >1) {
                cksum+=*buffer++;
                size -=sizeof(u_short);
        }
        if (size)
                cksum += *(u_char*)buffer;

        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >>16);
        return (u_short)(~cksum);
}

