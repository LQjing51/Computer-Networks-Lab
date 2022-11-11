#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *packet, int len, iface_info_t *iface, u8 type, u8 code) {
	struct ether_header *eh = (struct ether_header *) packet;
	struct iphdr *iph = packet_to_ip_hdr(packet);

	u16 icmp_data_len = IP_HDR_SIZE(iph) + ICMP_COPIED_DATA_LEN;
	u16 packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + icmp_data_len;
	char *new_packet = malloc(packet_len);

	// fill ICMP header and data
	char *buffer = malloc(icmp_data_len);
	memcpy(buffer, iph, icmp_data_len);
	struct icmphdr *ich = (struct icmphdr *) (new_packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	ich->type = type;
	ich->code = code;
	ich->icmp_identifier = ich->icmp_sequence = 0;
	memcpy((char *) ich + ICMP_HDR_SIZE, buffer, icmp_data_len);
	ich->checksum = icmp_checksum(ich, ICMP_HDR_SIZE + icmp_data_len);
	free(buffer);

	// fill ip header
	struct iphdr *new_iph = packet_to_ip_hdr(new_packet);
	u16 ip_total_len = IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + icmp_data_len;
	ip_init_hdr(new_iph, iface->ip, ntohl(iph->saddr), ip_total_len, IPPROTO_ICMP);

	// fill eth header
	struct ether_header *new_eh = (struct ether_header *) new_packet;
	new_eh->ether_type = htons(ETH_P_IP);
	memcpy(new_eh->ether_dhost, eh->ether_shost, ETH_ALEN);
	memcpy(new_eh->ether_shost, iface->mac, ETH_ALEN);

	free(packet);
	iface_send_packet(iface, new_packet, packet_len);
}