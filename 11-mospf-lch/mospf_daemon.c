#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "rtable.h"
#include "ether.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arp.h>

// const u8 allSPFRouteMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const u8 allSPFRouteMac[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x05};
// const u8 allSPFRouteMac[6] = {0x05, 0x00, 0x00, 0x5e, 0x00, 0x01};

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

char *generate_lsu_packet();
void send_lsu_packet(char *mospf_msg, iface_info_t *iface_nosend);
void db_fill_entry(mospf_db_entry_t *entry, u32 rid, struct mospf_lsu *lsu);
void update_rtable();
void dump_database();

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);

	while (1) {
		sleep(1);
		dump_database();
	}
}

void *sending_mospf_hello_thread(void *param)
{
	while (1) {
		sleep(1);
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			if (--iface->helloint == 0) {
				// generate mOSPF Hello message
				char *packet = malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
				
				struct mospf_hello *hello = (struct mospf_hello *) (packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
				mospf_init_hello(hello, iface->mask);
				
				struct mospf_hdr *mospf = (struct mospf_hdr *) (packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
				mospf_init_hdr(mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
				
				struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_SIZE);
				ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);
				
				struct ether_header *eh = (struct ether_header *) packet;
				eh->ether_type = htons(ETH_P_IP);
				memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
				memcpy(eh->ether_dhost, allSPFRouteMac, ETH_ALEN);

				printf("send hello packet on %s\n", iface->name);

				iface_send_packet(iface, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);

				iface->helloint = MOSPF_DEFAULT_HELLOINT;
			}
		}
	}

	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		int flag = 0;
		iface_info_t *iface = NULL;
		mospf_nbr_t *nbr = NULL, *nbr_ = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			list_for_each_entry_safe(nbr, nbr_, &iface->nbr_list, list) {
				if (--nbr->alive == 0) {
					list_delete_entry(&nbr->list);
					flag = 1;
				}
			}
		}
		if (flag) {
			// send lsu packet
			char *mospf_msg = generate_lsu_packet();
			send_lsu_packet(mospf_msg, NULL);
		}

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void *checking_database_thread(void *param)
{
	while (1) {
		sleep(1);
		
		pthread_mutex_lock(&mospf_lock);

		int flag = 0;
		mospf_db_entry_t *entry, *entry_;
		list_for_each_entry_safe(entry, entry_, &mospf_db, list) {
			if (--entry->alive == 0) {
				list_delete_entry(&entry->list);
				flag = 1;
			}
		}

		if (flag) update_rtable();

		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	pthread_mutex_lock(&mospf_lock);

	struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *) IP_DATA(ip);
	struct mospf_hello *hello = (struct mospf_hello *) (IP_DATA(ip) + MOSPF_HDR_SIZE);

	printf("recved mospf_hello from iface %s, rid = %d\n", iface->name, (int) ntohl(mospf->rid));


	u32 nbr_id = ntohl(mospf->rid);
	mospf_nbr_t *nbr = NULL;
	list_for_each_entry(nbr, &iface->nbr_list, list) {
		if (nbr->nbr_id == nbr_id) {
			// update alive time
			nbr->alive = ntohs(hello->helloint) * 3;
			pthread_mutex_unlock(&mospf_lock);
			return;
		}
	}

	// add new neighbor
	mospf_nbr_t *new_nbr = (mospf_nbr_t *) malloc(sizeof(mospf_nbr_t));
	new_nbr->nbr_id = nbr_id;
	new_nbr->nbr_ip = ntohl(ip->saddr);
	new_nbr->nbr_mask = ntohl(hello->mask);
	new_nbr->alive = ntohs(hello->helloint) * 3;
	list_add_head(&new_nbr->list, &iface->nbr_list);
	iface->num_nbr++;
	
	// send LSU packet for all iface
	char *mospf_msg = generate_lsu_packet();
	send_lsu_packet(mospf_msg, NULL);

	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	while (1) {
		sleep(1);
		if (--instance->lsuint == 0) {
			pthread_mutex_lock(&mospf_lock);

			char *mospf_msg = generate_lsu_packet();
			send_lsu_packet(mospf_msg, NULL);

			pthread_mutex_unlock(&mospf_lock);

			instance->lsuint = MOSPF_DEFAULT_LSUINT;
		}
	}

	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	pthread_mutex_lock(&mospf_lock);

	struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *) IP_DATA(ip);
	struct mospf_lsu *lsu = (struct mospf_lsu *) (IP_DATA(ip) + MOSPF_HDR_SIZE);

	printf("recved mospf_lsu from iface %s, rid = %d\n", iface->name, (int) ntohl(mospf->rid));

	u32 rid = ntohl(mospf->rid);

	mospf_db_entry_t *entry;
	list_for_each_entry(entry, &mospf_db, list) {
		if (entry->rid == rid) {
			if (entry->seq < ntohs(lsu->seq)) {
				db_fill_entry(entry, rid, lsu);
			}
			goto FORWARD;
		}
	}

	// insert a new entry
	mospf_db_entry_t *new_entry = (mospf_db_entry_t *) malloc(sizeof(mospf_db_entry_t));
	db_fill_entry(new_entry, rid, lsu);
	list_add_head(&new_entry->list, &mospf_db);

FORWARD:
	/* forward this packet */
	if (--lsu->ttl) {
		mospf->checksum = mospf_checksum(mospf);
		send_lsu_packet((char *) mospf, iface);
	}

	// update rtable
	update_rtable();

	pthread_mutex_unlock(&mospf_lock);
}

/* Generate LSU packet for this router.
   Assume that you have acquired mospf_lock. */
char *generate_lsu_packet() {
	instance->sequence_num++;

	iface_info_t *iface;
	mospf_nbr_t *nbr;

	int nadv = 0;
	list_for_each_entry(iface, &instance->iface_list, list) nadv += iface->num_nbr ? iface->num_nbr : 1;

	int mospf_len = MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + MOSPF_LSA_SIZE * nadv;
	char *mospf_msg = malloc(mospf_len);

	// fill mospf data
	struct mospf_lsu *lsu = (struct mospf_lsu *) (mospf_msg + MOSPF_HDR_SIZE);
	mospf_init_lsu(lsu, nadv);

	// fill every neighbor
	struct mospf_lsa *lsa = (char *) lsu + MOSPF_LSU_SIZE;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr == 0) {
			lsa->rid = 0; lsa->network = htonl(iface->ip); lsa->mask = htonl(iface->mask);
			lsa++;
			continue;
		}
		list_for_each_entry(nbr, &iface->nbr_list, list) {
			lsa->network = htonl(nbr->nbr_ip);
			lsa->mask = htonl(nbr->nbr_mask);
			lsa->rid = htonl(nbr->nbr_id);
			lsa++;
		}
	}

	// fill mospf header
	struct mospf_hdr *mospf = (struct mospf_hdr *) mospf_msg;
	mospf_init_hdr(mospf, MOSPF_TYPE_LSU, mospf_len, instance->router_id, instance->area_id);

	return mospf_msg;
}

/* Send MOSPF packet for every iface except for the one pass in.
   Assume that you have acquired mospf_lock. */
void send_lsu_packet(char *mospf_msg, iface_info_t *iface_nosend) {
	struct mospf_hdr *mospf = (struct mospf_hdr *) mospf_msg;
	int mospf_len = ntohs(mospf->len);

	iface_info_t *iface;
	mospf_nbr_t *nbr;

	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface == iface_nosend) continue;
		list_for_each_entry(nbr, &iface->nbr_list, list) {
			char *packet = malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mospf_len);
			// fill ip data
			memcpy(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE, mospf_msg, mospf_len);

			// fill ip header
			struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_SIZE);
			ip_init_hdr(ip, iface->ip, nbr->nbr_ip, IP_BASE_HDR_SIZE + mospf_len, IPPROTO_MOSPF);

			printf("send lsu packet on %s\n", iface->name);

			// send packet
			iface_send_packet_by_arp(iface, nbr->nbr_ip, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mospf_len);
		}
	}
}

/* Fill database entry with information in lsu. */
void db_fill_entry(mospf_db_entry_t *entry, u32 rid, struct mospf_lsu *lsu) {
	entry->rid = rid;
	entry->nadv = ntohl(lsu->nadv);
	entry->seq = ntohs(lsu->seq);

	entry->array = malloc(entry->nadv * MOSPF_LSA_SIZE);
	memcpy(entry->array, (char *) lsu + MOSPF_LSU_SIZE, entry->nadv * MOSPF_LSA_SIZE);
	
	entry->alive = MOSPF_DATABASE_TIMEOUT;
}

#define V 10
#define E 100

u32 to_rid[E];
int to[E], nx[E], h[V], num;
u32 rids[V];
int n;		// num of nodes

int dist[V], prev[V];
int sel[V];

void add_edge_raw(int x, u32 y) {
	to[++num] = y; nx[num] = h[x]; h[x] = num;
}

/* Update rtable entries.
   Assume that you have acquired mospf_lock. */
void update_rtable() {
	// TODO: We should acquire rtable lock here

	int i, j, k;
	iface_info_t *iface;
	mospf_nbr_t *nbr;

	// delete current entries
	rt_entry_t *rt_entry, *rt_entry_;
	list_for_each_entry_safe(rt_entry, rt_entry_, &rtable, list) {
		if (rt_entry->gw) {
			// this is the entry we inserted
			list_delete_entry(&rt_entry->list);
		}
	}

	// construct graph
	rids[n = 1] = instance->router_id;
	num = 0;
	mospf_db_entry_t *entry, *entry_;
	list_for_each_entry_safe(entry, entry_, &mospf_db, list) {
		rids[++n] = entry->rid;
		for (i = 0; i < entry->nadv; i++) {
			if (entry->array[i].rid)
				add_edge_raw(n, ntohl(entry->array[i].rid));
		}
	}
	for (i = 1; i <= n; i++)
		for (j = h[i]; j; j = nx[j]) {
			for (k = 1; k <= n; k++)
				if (to_rid[j] == rids[k]) {
					to[j] = k;
					break;
				}
			if (k > n) {
				printf("Update Rtable Error: in construct graph\n");
				return;
			}
		}

	// Dijistra
	dist[0] = n + 1;
	dist[1] = 0; prev[1] = -1; sel[1] = 0;
	for (i = 2; i <= n; i++) dist[i] = n + 1, sel[i] = 0;
	for (i = 1; i < n; i++) {
		// selet a node
		int u = 0;
		for (j = 1; j <= n; j++)
			if (!sel[j] && dist[j] < dist[u]) u = j;
		if (!u) break;	// cannot select node
		sel[u] = 1;
		// do relaxing
		for (j = h[i]; j; j = nx[j])
			if (dist[to[j]] > dist[u] + 1)
				dist[to[j]] = dist[u] + 1, prev[to[j]] = u;
	}

	// add new entries
	for (int i = 2; i <= n; i++)
		if (dist[i] < n + 1) {
			// get next node
			int lst, cur = i;
			while (cur != 1) lst = cur, cur = prev[cur];
			// find my iface to `lst`
			int flag = 0;
			iface_info_t *iface;
			list_for_each_entry(iface, &instance->iface_list, list) {
				list_for_each_entry(nbr, &iface->nbr_list, list) {
					if (nbr->nbr_id == rids[lst]) {
						flag = 1;
						break;
					}
				}
				if (flag) break;
			}
			if (!flag) {
				printf("Update Rtable Error: in find my iface\n");
				return;
			}
			iface_info_t *rt_iface = iface;
			u32 rt_gw = nbr->nbr_ip;

			// create rt entry
			list_for_each_entry(entry, &mospf_db, list) {
				if (entry->rid == rids[i]) {
					for (i = 0; i < entry->nadv; i++) {
						struct mospf_lsa *lsa = &entry->array[i];
						rt_entry_t *new_entry = new_rt_entry(ntohl(lsa->network), ntohl(lsa->mask), rt_gw, rt_iface);
						add_rt_entry(new_entry);
					}
				}
			}
		}
}

void dump_database() {
	pthread_mutex_lock(&mospf_lock);
	printf("Dump Database for rid = %d\n", (int) instance->router_id);
	mospf_db_entry_t *entry;
	list_for_each_entry(entry, &mospf_db, list) {
		printf("%d: %d\n", (int) entry->rid, entry->nadv);
	}
	fflush(stdout);
	pthread_mutex_unlock(&mospf_lock);
}


void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

