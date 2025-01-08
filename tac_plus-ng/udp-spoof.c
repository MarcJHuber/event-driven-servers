/*
   Copyright (C) 2024-2025 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

#include "headers.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include "misc/net.h"

#define BUFFER_SIZE 4096

struct udp_pseudo_header {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint32_t length;
    uint8_t zeros[3];
    uint8_t next_header;
} __attribute__((__packed__));;

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
	sum += *buf++;
    if (len == 1)
	sum += *(unsigned char *) buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

ssize_t sendto_spoof(sockaddr_union *src_addr, sockaddr_union *dest_addr, void *buf, size_t buf_len)
{
    int sock = socket(src_addr->sa.sa_family, SOCK_RAW, IPPROTO_RAW);
fprintf(stderr ,"sock =%d\n", sock);
    if (sock < 0)
	return -1;

    size_t buffer_len = 0;
    u_char *buffer = NULL;
    struct udphdr *udp = NULL;

    if (src_addr->sa.sa_family == AF_INET) {

#ifdef IP_HDRINCL
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
#endif

	buffer_len = sizeof(struct ip) + sizeof(struct udphdr) + buf_len;
	buffer = alloca(buffer_len);
	memset(buffer, 0, buffer_len);

	struct ip *ip = (struct ip *) buffer;
	udp = (struct udphdr *) (buffer + sizeof(struct ip));
	u_char *data = buffer + sizeof(struct ip) + sizeof(struct udphdr);

	memcpy(data, buf, buf_len);

	ip->ip_v = 4;
	ip->ip_hl = 5;
	buffer_len = sizeof(struct ip) + sizeof(struct udphdr) + buf_len;
	ip->ip_len = htons(buffer_len);
	ip->ip_id = rand();
	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_src.s_addr = src_addr->sin.sin_addr.s_addr;
	ip->ip_dst.s_addr = dest_addr->sin.sin_addr.s_addr;
	ip->ip_sum = checksum(ip, sizeof(struct ip));

    while (!udp->uh_sport)
	udp->uh_sport = htons((short) ((0x8000 | rand()) & 0x7fff));
    udp->uh_dport = htons(su_get_port(dest_addr));
    udp->uh_ulen = htons(sizeof(struct udphdr) + buf_len);

    } else if (src_addr->sa.sa_family == AF_INET6) {
	buffer_len = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + buf_len;
	buffer = alloca(buffer_len);
	memset(buffer, 0, buffer_len);

	struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
	udp = (struct udphdr *) (buffer + sizeof(struct ip6_hdr));
	u_char *data = buffer + sizeof(struct ip6_hdr) + sizeof(struct udphdr);

	memcpy(data, buf, buf_len);

	ip6->ip6_flow = htonl((6 << 28));	// version
	ip6->ip6_plen = htons(sizeof(struct udphdr) + buf_len);
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hops = 64;
	ip6->ip6_src = src_addr->sin6.sin6_addr;
	ip6->ip6_dst = dest_addr->sin6.sin6_addr;

    struct udp_pseudo_header pseudo_header = {
	.src_addr = ip6->ip6_src,
	.dst_addr = ip6->ip6_dst,
	.length = udp->uh_ulen,
	.next_header = IPPROTO_UDP
    };
    char checksum_buffer[sizeof(struct udp_pseudo_header) + sizeof(struct udphdr) + buf_len];
    memcpy(checksum_buffer, &pseudo_header, sizeof(struct udp_pseudo_header));
    memcpy(checksum_buffer + sizeof(struct udp_pseudo_header), udp, sizeof(struct udphdr) + buf_len);
    udp->uh_sum = checksum(checksum_buffer, sizeof(checksum_buffer));
    }

    int res = sendto(sock, buffer, buffer_len, 0, &dest_addr->sa, sizeof(dest_addr->sa));
fprintf(stderr ,"res =%d errno=%d err=%s\n", res, errno, strerror(errno));
    close(sock);
    return res;
}
