#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	u8 len = ETHER_HDR_SIZE+sizeof(struct ether_arp)
	char* packet = malloc(len);
	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arph = (struct ether_arp *)(packet+ETHER_HDR_SIZE);

	memset(eh->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);

	arph->arp_op =  htons(ARPOP_REQUEST);
	memcpy(arph->arp_sha,iface->mac,ETH_ALEN);
	arph->arp_spa = ntohl(iface->ip);
	memset(arph->arp_tha,0,ETH_ALEN);
	arph->arp_tpa = dst_ip;

	iface_send_packet(iface, packet, len);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	u8 len = ETHER_HDR_SIZE+sizeof(struct ether_arp)
	char* packet = malloc(len);
	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arph = (struct ether_arp *)(packet+ETHER_HDR_SIZE);

	memcpy(eh->ether_dhost, req_hdr->ether_shost, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);

	arph->arp_op =  htons(ARPOP_REPLY);
	memcpy(arph->arp_sha,iface->mac,ETH_ALEN);
	arph->arp_spa = ntohl(iface->ip);
	memcpy(arph->arp_tha,req_hdr->arp_sha,ETH_ALEN);
	arph->arp_tpa = req_hdr->arp_spa;

	iface_send_packet(iface, packet, len);

}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");

	struct ether_arp {
    u16 arp_hrd;		/* Format of hardware address.  */
    u16 arp_pro;		/* Format of protocol address.  */
    u8	arp_hln;		/* Length of hardware address.  */
    u8	arp_pln;		/* Length of protocol address.  */
    u16 arp_op;			/* ARP opcode (command).  */
	u8	arp_sha[ETH_ALEN];	/* sender hardware address */
	u32	arp_spa;		/* sender protocol address */
	u8	arp_tha[ETH_ALEN];	/* target hardware address */
	u32	arp_tpa;		/* target protocol address */
} __attribute__ ((packed));
	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arph = (struct ether_arp *)(packet+ETHER_HDR_SIZE);
	if (ntohs(arph->arp_op)  == ARPOP_REQUEST) {
		if (ntohl(arph->arp_tpa) == iface->ip) {
			arp_send_reply(iface,arph);
		}
	}else if (ntohs(arph->arp_op)  == ARPOP_REPLY) {
		arpcache_insert(ntohl(arph->arp_spa), arph->arp_sha);
	}


}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
