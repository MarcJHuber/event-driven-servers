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
    if (sock < 0)
	return -1;

    size_t buffer_len = 0;
    u_char *buffer = NULL;
    struct udphdr *udp = NULL;

    if (src_addr->sa.sa_family == AF_INET) {
#ifdef __ANY_BSD__
#define iphdr ip
#define version ip_v
#define ihl ip_hl
#define tot_len ip_len
#define id ip_id
#define ttl ip_ttl
#define protocol ip_p
#define saddr ip_src.s_addr
#define daddr ip_dst.s_addr
#define check ip_sum
#endif
	buffer_len = sizeof(struct iphdr) + sizeof(struct udphdr) + buf_len;
	char *buffer = alloca(buffer_len);
	memset(buffer, 0, buffer_len);

	struct iphdr *ip = (struct iphdr *) buffer;
	udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
	char *data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);

	memcpy(data, buf, buf_len);

	ip->version = 4;
	ip->ihl = 5;
	buffer_len = sizeof(struct iphdr) + sizeof(struct udphdr) + buf_len;
	ip->tot_len = htons(buffer_len);
	ip->id = htons(rand());
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = src_addr->sin.sin_addr.s_addr;
	ip->daddr = dest_addr->sin.sin_addr.s_addr;
	ip->check = checksum(ip, sizeof(struct iphdr));

    } else if (src_addr->sa.sa_family == AF_INET6) {
	buffer_len = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + buf_len;
	char *buffer = alloca(buffer_len);
	memset(buffer, 0, buffer_len);

	struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
	udp = (struct udphdr *) (buffer + sizeof(struct ip6_hdr));
	char *data = buffer + sizeof(struct ip6_hdr) + sizeof(struct udphdr);

	memcpy(data, buf, buf_len);

	ip6->ip6_flow = htonl((6 << 28));	// version
	ip6->ip6_plen = htons(sizeof(struct udphdr) + buf_len);
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hops = 64;
	memcpy(&ip6->ip6_src, &src_addr->sin6.sin6_addr, 16);
	memcpy(&ip6->ip6_dst, &dest_addr->sin6.sin6_addr, 16);
    }

#ifdef __ANY_BSD__
#define source uh_sport
#define dest uh_dport
#define len uh_ulen
#endif
    while (!udp->source)
	udp->source = htons((short) ((0x8000 | rand()) & 0xfff));
    udp->dest = htons(su_get_port(dest_addr));
    udp->len = htons(sizeof(struct udphdr) + buf_len);

    int res = sendto(sock, buffer, buffer_len, 0, &dest_addr->sa, sizeof(dest_addr->sa));
    close(sock);
    return res;
}
