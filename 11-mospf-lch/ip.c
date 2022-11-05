#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *) packet;
	struct iphdr *iph = packet_to_ip_hdr(packet);

	u32 daddr = ntohl(iph->daddr);
	if (daddr == iface->ip) {
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
		} else if (iph->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
			free(packet);
			return;
		}
	}

	if (daddr == MOSPF_ALLSPFRouters) {
		assert(iph->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);
		free(packet);
		return;
	}

	/* Forward Packet */

	/* lookup in route table */
	rt_entry_t *entry = longest_prefix_match(ntohl(iph->daddr));
	if (!entry) {
		// reply ICMP_DEST_UNREACH
		// printf("handle_ip_packet: send ICMP_DEST_UNREACH\n");
		send_icmp_packet(packet, iface, ICMP_DEST_UNREACH, 0);
		return;
	}

	/* substract 1 from ttl */
	if (!(--iph->ttl)) {
		// reply ICMP_TIME_EXCEEDED
		// printf("handle_ip_packet: send ICMP_TIME_EXCEEDED\n");
		send_icmp_packet(packet, iface, ICMP_TIME_EXCEEDED, 0);
		return;
	}
	iph->checksum = ip_checksum(iph);

	/* forward packet */
	u32 dest_ip_addr = entry->gw ? entry->gw : ntohl(iph->daddr);
	// printf("handle_ip_packet: forward, dest_ip = %x\n", dest_ip_addr);
	iface_send_packet_by_arp(entry->iface, dest_ip_addr, packet, len);
}

void send_icmp_packet(char *packet, iface_info_t *iface, u8 type, u8 code) {
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
