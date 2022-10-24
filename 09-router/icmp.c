#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	fprintf(stderr, "TODO: malloc and send icmp packet.\n");

	struct ether_header *eh = (struct ether_header *)in_pkt;
	struct iphdr *iph = (struct iphdr *)(in_pkt+ETHER_HDR_SIZE);
	char* packet;
	int new_len = 0;
	if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		printf("icmp packet: dest unreach || time exceeded\n");
		new_len = ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_COPIED_DATA_LEN;
		packet = (char*)malloc(new_len);
		memcpy(packet, in_pkt, ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE - 4);
		memset(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE - 4, 0, 4);
		memcpy(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(iph) + ICMP_HDR_SIZE, iph, IP_HDR_SIZE(iph) + ICMP_COPIED_DATA_LEN);
	}else {
		printf("icmp packet: echo reply\n");
		new_len = len;
		packet = (char*)malloc(new_len);
		memcpy(packet,in_pkt,len);
	}
	
	eh = (struct ether_header *)packet;
	iph = (struct iphdr *)(packet+ETHER_HDR_SIZE);

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &(instance->iface_list), list) {
		if(!memcmp(eh->ether_dhost,iface->mac,ETH_ALEN)) break;
	}

	memcpy(eh->ether_dhost,eh->ether_shost,ETH_ALEN);
	memcpy(eh->ether_shost,iface->mac,ETH_ALEN);
	
	u32 new_saddr = ntohl(iph->daddr);
	u32 new_daddr = ntohl(iph->saddr);
	u8 proto = iph->protocol;
	ip_init_hdr(iph, new_saddr, new_daddr, new_len-ETHER_HDR_SIZE, proto);

	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(iph);
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = icmp_checksum(icmp, new_len-ETHER_HDR_SIZE-IP_HDR_SIZE(iph));
	
	
	iface_send_packet(iface, packet, new_len);
}
