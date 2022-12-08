#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

static void arp_send_packet(iface_info_t *iface, u16 arp_op, u8 arp_tha[ETH_ALEN], u32 arp_tpa);

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	// printf("send arp request, ip = %x\n", dst_ip);
	u8 broadcast_mac[ETH_ALEN];
	int i;
	for (i = 0; i < ETH_ALEN; i++) broadcast_mac[i] = 0xff;
	arp_send_packet(iface, ARPOP_REQUEST, broadcast_mac, dst_ip);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	// printf("send arp reply, ip = %x\n", ntohl(req_hdr->arp_spa));
	arp_send_packet(iface, ARPOP_REPLY, req_hdr->arp_sha, ntohl(req_hdr->arp_spa));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *ah = (struct ether_arp *) (packet + ETHER_HDR_SIZE);
	if (ntohs(ah->arp_op) == ARPOP_REPLY) {
		// printf("received arp reply, ip = %x\n", ntohl(ah->arp_spa));
		arpcache_insert(ntohl(ah->arp_spa), ah->arp_sha);
	} else if (ntohs(ah->arp_op) == ARPOP_REQUEST) {
		// printf("received arp request, %x %x\n", iface->ip, ntohl(ah->arp_tpa));
		if (iface->ip == ntohl(ah->arp_tpa)) arp_send_reply(iface, ah);
	} else {
		fprintf(stderr, "Cannot recognize arp_op.\n");
	}
	free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_IP);

	// printf(""IP_FMT"\n", LE_IP_FMT_STR(dst_ip));
	// printf("%s\n", iface->name);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);

	// printf("%d\n", found);

	if (found) {
		// printf("iface_send_packet_by_arp: found the mac of %x, send this packet\n", dst_ip);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// printf("iface_send_packet_by_arp: find %x failed, pend this packet %llx\n", dst_ip, packet);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}

static void arp_send_packet(iface_info_t *iface, u16 arp_op, u8 arp_tha[ETH_ALEN], u32 arp_tpa) {
	u16 total_len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
	char *packet = malloc(total_len);
	// fill arp header
	struct ether_arp *ah = (struct ether_arp *) (packet + ETHER_HDR_SIZE);
	ah->arp_hrd = htons(ARPHRD_ETHER);
	ah->arp_pro = htons(ETH_P_IP);
	ah->arp_hln = 6;
	ah->arp_pln = 4;
	ah->arp_op = htons(arp_op);
	memcpy(ah->arp_sha, iface->mac, ETH_ALEN);
	ah->arp_spa = htonl(iface->ip);
	memcpy(ah->arp_tha, arp_tha, ETH_ALEN);
	ah->arp_tpa = htonl(arp_tpa);

	// fill eth header
	struct ether_header *eh = (struct ether_header *) packet;
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eh->ether_dhost, arp_tha, ETH_ALEN);

	iface_send_packet(iface, packet, total_len);
}
