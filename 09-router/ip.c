#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "rtable.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: handle ip packet.\n");
	//struct ether_header *eh = (struct ether_header *)packet;
	struct iphdr *iph = (struct iphdr *)(packet+ETHER_HDR_SIZE);
	struct icmphdr *icmph = (struct icmphdr *)IP_DATA(iph);
	if (iph->protocol == IPPROTO_ICMP && icmph->type == ICMP_ECHOREQUEST && ntohl(iph->daddr) == iface->ip) {
		printf("ip packet: icmp type == icmp echo request\n"); 
		icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
	}else {
		printf("ip packet: need forward\n"); 
		//ip_send_packet(packet, len);
		//iface_send_packet_by_arp(iface, iph->daddr, packet,len);
		printf("ttl = %d\n",iph->ttl);
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

}
