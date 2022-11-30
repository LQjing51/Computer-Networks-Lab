#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

// #include "log.h"

#include <stdio.h>
#include <stdlib.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
	//fprintf(stderr, "TODO: longest prefix match for the packet.\n");
	rt_entry_t *entry = NULL;
	rt_entry_t *longest = NULL;
	u32 long_mask = 0;
	list_for_each_entry(entry, &rtable, list) {
		if ((dst & entry->mask) == (entry->dest & entry->mask)) {
			if (entry->mask > long_mask) {
				long_mask = entry->mask;
				longest = entry;
			}
		}
	}
	return longest;
}

// send IP packet
//
// Different from forwarding packet, ip_send_packet sends packet generated by
// router itself. This function is used to send ICMP packets.
void ip_send_packet(char *packet, int len)
{
	//fprintf(stderr, "TODO: send ip packet.\n");

	struct ether_header *eh = (struct ether_header*)packet;
	struct iphdr *iph = (struct iphdr *) (packet+ETHER_HDR_SIZE);
	iface_info_t *iface;
	int flag = 0;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if(iface->ip == ntohl(iph->saddr)) {
			flag = 1;
			break;
		}
	}
	if (!flag){printf("ip send packet error\n"); return;}
	iface_send_packet_by_arp(iface, ntohl(iph->daddr),packet,len);
}
