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

	struct ether_header *eh0 = (struct ether_header *)in_pkt;
	struct iphdr *iph0 = (struct iphdr *)(in_pkt+ETHER_HDR_SIZE);
	char* packet;
	int new_len = 0;
	if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		printf("icmp packet: dest unreach || time exceeded\n");
		// printf("origin header size = %d\n",IP_HDR_SIZE(iph0));
		new_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(iph0) + ICMP_COPIED_DATA_LEN;
		packet = (char*)malloc(new_len);
		memset(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE - 4, 0, 4);
		memcpy(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE, (char*)iph0, IP_HDR_SIZE(iph0) + ICMP_COPIED_DATA_LEN);
	}else {
		printf("icmp packet: echo reply\n");
		new_len = len - IP_HDR_SIZE(iph0) + IP_BASE_HDR_SIZE;
		packet = (char*)malloc(new_len);
		memcpy(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE - 4, (char*)iph0 + IP_HDR_SIZE(iph0) + ICMP_HDR_SIZE - 4, len - ETHER_HDR_SIZE - IP_HDR_SIZE(iph0) - ICMP_HDR_SIZE + 4);
		//memcpy(packet, iph0 + IP_HDR_SIZE(iph0), len);
		//new_len = len;
		//packet = (char*)malloc(new_len);
		//memcpy(packet,in_pkt,new_len);
	}
	
	struct ether_header *eh = (struct ether_header *)packet;
	struct iphdr *iph = (struct iphdr *)(packet+ETHER_HDR_SIZE);

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &(instance->iface_list), list) {
		if(!memcmp(eh0->ether_dhost,iface->mac,ETH_ALEN)) break;
	}
	printf("send icmp packet:iface->name = %s\n",iface->name);
	memcpy(eh->ether_dhost,eh0->ether_shost,ETH_ALEN);
	memcpy(eh->ether_shost,iface->mac,ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u32 new_saddr = iface->ip;
	u32 new_daddr = ntohl(iph0->saddr);
	u8 proto = IPPROTO_ICMP;
	printf("send icmp packet:saddr ip = ");
	printf(IP_FMT,LE_IP_FMT_STR(new_saddr));
	printf("\n");
	printf("send icmp packet:daddr ip = ");
	printf(IP_FMT,LE_IP_FMT_STR(new_daddr));
	printf("\n");	
	ip_init_hdr(iph, new_saddr, new_daddr, new_len-ETHER_HDR_SIZE, proto);

	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(iph);
	icmp->type = type;
	icmp->code = code;
	icmp->checksum = icmp_checksum(icmp, new_len-ETHER_HDR_SIZE-IP_HDR_SIZE(iph));
	
	
	iface_send_packet(iface, packet, new_len);
}
