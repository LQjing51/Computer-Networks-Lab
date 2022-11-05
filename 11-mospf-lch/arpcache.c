#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	int i;
	for (i = 0; i < MAX_ARP_SIZE; i++) {
		struct arp_cache_entry *entry = arpcache.entries + i;
		if (entry->valid && entry->ip4 == ip4) {
			memcpy(mac, entry->mac, ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	pthread_mutex_lock(&arpcache.lock);
	struct cached_pkt *cpkt = (struct cached_pkt *) malloc(sizeof(struct cached_pkt));
	cpkt->packet = packet;
	cpkt->len = len;
	struct arp_req *entry;
	list_for_each_entry(entry, &arpcache.req_list, list) {
		if (entry->iface == iface && entry->ip4 == ip4) {
			list_add_tail(&cpkt->list, &entry->cached_packets);
			pthread_mutex_unlock(&arpcache.lock);
			return;
		}
	}
	// add a new arp_req
	struct arp_req *req = (struct arp_req *) malloc(sizeof(struct arp_req));
	req->iface = iface;
	req->ip4 = ip4;
	time(&req->sent);
	req->retries = 0;
	init_list_head(&req->cached_packets);
	list_add_tail(&cpkt->list, &req->cached_packets);
	// append new arp_req to req_list
	list_add_tail(&req->list, &arpcache.req_list);
	// send arp request
	arp_send_request(iface, ip4);
	pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// printf("in arpcache_insert.\n");
	pthread_mutex_lock(&arpcache.lock);
	int i;
	for (i = 0; i < MAX_ARP_SIZE; i++) {
		struct arp_cache_entry *entry = arpcache.entries + i;
		if (entry->valid && entry->ip4 == ip4) {
			pthread_mutex_unlock(&arpcache.lock);
			return;
		}
	}

	// insert new entry
	for (i = 0; i < MAX_ARP_SIZE; i++) {
		struct arp_cache_entry *entry = arpcache.entries + i;
		if (!entry->valid) {
			entry->ip4 = ip4;
			memcpy(entry->mac, mac, ETH_ALEN);
			time(&entry->added);
			entry->valid = 1;
		}
	}
	if (i == MAX_ARP_SIZE) {
		// need replace
		int idx = rand() % MAX_ARP_SIZE;
		struct arp_cache_entry *entry = arpcache.entries + idx;
		entry->ip4 = ip4;
		memcpy(entry->mac, mac, ETH_ALEN);
		time(&entry->added);
		entry->valid = 1;
	}

	// check pend list
	struct arp_req *entry, *entry_;
	list_for_each_entry_safe(entry, entry_, &arpcache.req_list, list) {
		if (entry->ip4 == ip4) {
			// printf("arpcache_insert: sending pend packet.\n");
			struct cached_pkt *cpkt, *cpkt_;
			list_for_each_entry_safe(cpkt, cpkt_, &entry->cached_packets, list) {
				struct ether_header *eh = (struct ether_header *) cpkt->packet;
				memcpy(eh->ether_shost, entry->iface->mac, ETH_ALEN);
				memcpy(eh->ether_dhost, mac, ETH_ALEN);
				// printf("arpcache_insert: send pend packet %llx\n", cpkt->packet);
				iface_send_packet(entry->iface, cpkt->packet, cpkt->len);
				list_delete_entry(&cpkt->list);
				free(cpkt);
			}
			list_delete_entry(&entry->list);
			free(entry);
		}
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		time_t cur_time;
		time(&cur_time);
		int i;
		for (i = 0; i < MAX_ARP_SIZE; i++) {
			struct arp_cache_entry *entry = arpcache.entries + i;
			if (entry->valid && cur_time - entry->added >= ARP_ENTRY_TIMEOUT) {
				entry->valid = 0;
			}
		}
		
		struct arp_req *entry, *entry_;
		list_for_each_entry_safe(entry, entry_, &arpcache.req_list, list) {
			if (cur_time - entry->sent >= 1) {
				if (++entry->retries == ARP_REQUEST_MAX_RETRIES) {
					// reply ICMP_DEST_UNREACH
					struct cached_pkt *cpkt, *cpkt_;
					list_for_each_entry_safe(cpkt, cpkt_, &entry->cached_packets, list) {
						struct ether_header *eh = (struct ether_header *) cpkt->packet;
						// find which iface it comes from
						int flag = 0;
						iface_info_t *iface;
						list_for_each_entry(iface, &instance->iface_list, list) {
							// compare mac address
							int j;
							for (j = 0; j < ETH_ALEN; j++)
								if (iface->mac[j] != eh->ether_dhost[j]) break;
							if (j == ETH_ALEN) {
								// found iface
								send_icmp_packet(cpkt->packet, iface, ICMP_DEST_UNREACH, 1);
								flag = 1;
								break;
							}
						}
						if (!flag) {
							fprintf(stderr, "Cannot find iface.\n");
						}
						list_delete_entry(&cpkt->list);
						free(cpkt);
					}
					list_delete_entry(&entry->list);
					free(entry);
				} else {
					arp_send_request(entry->iface, entry->ip4);
					time(&entry->sent);
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
