#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}

		free(packet);
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
		assert(ip->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}

void ip_forward_packet(u32 dst, char *packet, int len) {
	printf("ip packet: need forward\n"); 
	struct iphdr *iph = packet_to_ip_hdr(packet);
	if (--(iph->ttl) <= 0) {
		icmp_send_packet(packet,len,ICMP_TIME_EXCEEDED,ICMP_EXC_TTL);
		return;
	}
	iph->checksum = ip_checksum(iph);

	rt_entry_t *res = longest_prefix_match(ntohl(iph->daddr));
	if (!res) {
		icmp_send_packet(packet,len,ICMP_DEST_UNREACH,ICMP_NET_UNREACH);
		return;
	}
	u32 dst_ip;
	if (!res->gw) dst_ip = ntohl(iph->daddr);
	else dst_ip = res->gw;
	iface_send_packet_by_arp(res->iface, dst_ip, packet, len);


}