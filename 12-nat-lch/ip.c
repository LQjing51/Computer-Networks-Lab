#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "nat.h"

#include <stdlib.h>
#include <string.h>

void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *) packet;
	struct iphdr *iph = packet_to_ip_hdr(packet);
	/* check if the packet is ICMP echo request */
	if (iph->protocol == IPPROTO_ICMP) {
		struct icmphdr *ich = (struct icmphdr *) IP_DATA(iph);
		if (ich->type == ICMP_ECHOREQUEST && ntohl(iph->daddr) == iface->ip) {
			// change packet to ICMP echo reply
			ich->type = 0;
			ich->code = 0;
			ich->checksum = icmp_checksum(ich, len - ETHER_HDR_SIZE - IP_HDR_SIZE(iph));
			iph->daddr = iph->saddr;
			iph->saddr = htonl(iface->ip);
			iph->checksum = ip_checksum(iph);
			// set mac address
			memcpy(eh->ether_dhost, eh->ether_shost, ETH_ALEN);
			memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
			// send packet
			iface_send_packet(iface, packet, len);
			return;
		}
	}
	else {
		nat_translate_packet(iface, packet, len);
	}
}

