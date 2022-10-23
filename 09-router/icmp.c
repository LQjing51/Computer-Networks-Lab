#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	fprintf(stderr, "TODO: malloc and send icmp packet.\n");

	struct ether_header *eh = (struct ether_header *)in_pkt;
	struct iphdr *iph = (struct iphdr *)(in_pkt+ETHER_HDR_SIZE);

	if (type == ICMP_DEST_UNREACH || ICMP_TIME_EXCEEDED) {
		char* packet = (char*)malloc(ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_COPIED_DATA_LEN);
		memcpy(packet, in_pkt, ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE - 4);
		memset(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE - 4, 0, 4);
		memcpy(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE, iph, IP_HDR_SIZE(iph) + ICMP_COPIED_DATA_LEN);
	}else {
		char* packet = (char*)malloc(len);
		memcpy(packet,in_pkt,len);
	}
	
	eh = (struct ether_header *)packet;
	iph = (struct iphdr *)(packet+ETHER_HDR_SIZE);

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &(instance->iface_list), list) {
		if(!memcmp(eh->ether_dhost,iface->mac)) break;
	}
	u8 old_shost[ETH_ALEN];
	memcpy(old_shost,eh->ether_shost,ETH_ALEN);
	memcpy(eh->ether_shost,eh->ether_dhost,ETH_ALEN);
	memcpy(eh->ether_dhost,old_shost,ETH_ALEN);
	
	u32 new_saddr = ntohl(iph->daddr);
	u32 new_daddr = ntohl(iph->saddr);
	u8 proto = iph->protocol;
	ip_init_hdr(iph, new_saddr, new_daddr, len, proto);

	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(iph);
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = icmp_checksum(icmp, len-ETHER_HDR_SIZE-IP_HDR_SIZE(iph));
	
	
	iface_send_packet(iface, packet, len)
}
