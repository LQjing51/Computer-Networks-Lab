#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "arp.h"
#include "ip.h"
#include "rtable.h"
#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
const int INT_MAX = 100;
extern ustack_t *instance;

pthread_mutex_t mospf_lock;

char *current_lsu();
void send_from_ifaces(char *lsu_packet, iface_info_t *myiface);
void update_rtable();
void print_database();
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
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		iface->num_nbr = 0;
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
}

void *sending_mospf_hello_thread(void *param)
{
	while (1)
	{
		sleep(1);
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list)
		{
			if (--iface->helloint == 0)
			{
				int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
				char *packet = malloc(len);
				struct ether_header *eh = (struct ether_header *)packet;
				struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
				struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);
				struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);

				memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
				u8 MOSPF_AllSPFRoutersMac[ETH_ALEN] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x05};
				memcpy(eh->ether_dhost, MOSPF_AllSPFRoutersMac, ETH_ALEN);
				eh->ether_type = htons(ETH_P_IP);
				ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);
				mospf_init_hello(hello, iface->mask);
				mospf_init_hdr(mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);

				iface_send_packet(iface, packet, len);

				iface->helloint = MOSPF_DEFAULT_HELLOINT;
			}
		}
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	// fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while (1)
	{
		sleep(1);
		pthread_mutex_lock(&mospf_lock);
		int delete = 0;
		iface_info_t *iface = NULL;
		mospf_nbr_t *neighbor = NULL, *neighbor_safe = NULL;
		list_for_each_entry(iface, &instance->iface_list, list)
		{
			list_for_each_entry_safe(neighbor, neighbor_safe, &iface->nbr_list, list)
			{
				if (--neighbor->alive == 0)
				{
					list_delete_entry(&neighbor->list);
					iface->num_nbr--;
					delete = 1;
				}
			}
		}

		if (delete)
		{
			char *lsu_packet = current_lsu();
			send_from_ifaces(lsu_packet, NULL);
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_database_thread(void *param)
{

	while (1)
	{
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		// printf("checking database....\n");

		int delete = 0;
		mospf_db_entry_t *entry = NULL, *entry_safe = NULL;
		list_for_each_entry_safe(entry, entry_safe, &mospf_db, list)
		{
			// printf("entry->rid = %hhu.%hhu.%hhu.%hhu,seq = %d, alive = %d\n",LE_IP_FMT_STR(entry->rid),entry->seq,entry->alive);
			if (--entry->alive == 0)
			{
				list_delete_entry(&entry->list);
				delete = 1;
			}
		}

		if (delete)
		{
			// printf("[database has deleted]database print\n");
			// print_database();
			update_rtable();
		}
		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	pthread_mutex_lock(&mospf_lock);
	// fprintf(stdout, "TODO: handle mOSPF Hello message.\n");

	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);

	// check whether in neighbor list
	mospf_nbr_t *neighbor = NULL;
	list_for_each_entry(neighbor, &iface->nbr_list, list)
	{
		if (neighbor->nbr_id == ntohl(mospf->rid))
		{
			neighbor->alive = 3 * ntohs(hello->helloint);
			pthread_mutex_unlock(&mospf_lock);
			return;
		}
	}
	// add new neighbor
	mospf_nbr_t *new_nbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
	new_nbr->nbr_id = ntohl(mospf->rid);
	new_nbr->nbr_ip = ntohl(ip->saddr);
	new_nbr->nbr_mask = ntohl(hello->mask);
	new_nbr->alive = 3 * ntohs(hello->helloint);
	list_add_head(&new_nbr->list, &iface->nbr_list);
	iface->num_nbr++;

	// get now lsu info
	char *lsu_packet = current_lsu();
	// send out
	send_from_ifaces(lsu_packet, NULL);

	pthread_mutex_unlock(&mospf_lock);
}
char *current_lsu()
{
	// collect router's all neighbor info
	iface_info_t *iface_tmp = NULL;
	int total_neighbor = 0;
	list_for_each_entry(iface_tmp, &instance->iface_list, list)
	{
		// printf("add neighbor = %d",iface_tmp->num_nbr == 0 ? 1:iface_tmp->num_nbr);
		if (iface_tmp->num_nbr == 0)
			total_neighbor += 1;
		else
			total_neighbor += iface_tmp->num_nbr;
	}
	// printf("collect neighbor info, total_neighbor = %d\n",total_neighbor);
	char *nbr_data = malloc(total_neighbor * MOSPF_LSA_SIZE);
	struct mospf_lsa *lsa = (struct mospf_lsa *)nbr_data;
	list_for_each_entry(iface_tmp, &instance->iface_list, list)
	{
		if (iface_tmp->num_nbr > 0)
		{
			mospf_nbr_t *neighbor = NULL;
			list_for_each_entry(neighbor, &iface_tmp->nbr_list, list)
			{
				lsa->rid = htonl(neighbor->nbr_id);
				lsa->mask = htonl(neighbor->nbr_mask);
				lsa->network = htonl(neighbor->nbr_ip);
				lsa = (struct mospf_lsa *)((char *)lsa + MOSPF_LSA_SIZE);
			}
		}
		else
		{
			lsa->rid = 0;
			lsa->mask = htonl(iface_tmp->mask);
			lsa->network = htonl(iface_tmp->ip);
			lsa = (struct mospf_lsa *)((char *)lsa + MOSPF_LSA_SIZE);
		}
	}
	// malloc lsu packet and fill header
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_neighbor * MOSPF_LSA_SIZE;
	char *lsu_packet = malloc(len);
	struct ether_header *eh = (struct ether_header *)lsu_packet;
	struct iphdr *ip = (struct iphdr *)(lsu_packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);
	struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	char *data = (char *)lsu + MOSPF_LSU_SIZE;
	mospf_init_lsu(lsu, total_neighbor);
	memcpy(data, nbr_data, total_neighbor * MOSPF_LSA_SIZE);
	mospf_init_hdr(mospf, MOSPF_TYPE_LSU, len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE, instance->router_id, instance->area_id);
	instance->sequence_num++;
	return lsu_packet;
}
void send_from_ifaces(char *lsu_packet, iface_info_t *myiface)
{
	struct ether_header *eh = (struct ether_header *)lsu_packet;
	struct iphdr *ip = (struct iphdr *)(lsu_packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);
	u16 ip_packt_len = ntohs(mospf->len) + IP_BASE_HDR_SIZE;
	u16 lsu_packet_len = ip_packt_len + ETHER_HDR_SIZE;
	// printf("mospf->len = %d\n",mospf->len);
	// printf("lsu_packet_len = %d\n",lsu_packet_len);
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		if (iface == myiface)
			continue;
		mospf_nbr_t *neighbor = NULL;
		list_for_each_entry(neighbor, &iface->nbr_list, list)
		{
			char *packet = malloc(lsu_packet_len);
			u32 daddr = neighbor->nbr_ip;
			ip_init_hdr(ip, iface->ip, daddr, ip_packt_len, IPPROTO_MOSPF);
			memcpy(packet, lsu_packet, lsu_packet_len);
			iface_send_packet_by_arp(iface, neighbor->nbr_ip, packet, lsu_packet_len);
		}
	}
}
void *sending_mospf_lsu_thread(void *param)
{

	while (1)
	{
		sleep(1);
		if (--instance->lsuint == 0)
		{
			pthread_mutex_lock(&mospf_lock);

			char *lsu_packet = current_lsu();
			send_from_ifaces(lsu_packet, NULL);

			pthread_mutex_unlock(&mospf_lock);

			instance->lsuint = MOSPF_DEFAULT_LSUINT;
		}
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	pthread_mutex_lock(&mospf_lock);
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	u32 rid = ntohl(mospf->rid);
	// fprintf(stdout, "TODO: handle mOSPF LSU message.rid = %hhu.%hhu.%hhu.%hhu\n",LE_IP_FMT_STR(rid));
	//do not handle my lsu packet, avoiding circle 
	// if (ntohl(mospf->rid) == instance->router_id){
	// 	printf("receive my lsu packet\n");
	// 	pthread_mutex_unlock(&mospf_lock);
	// 	return;
	// }
	// update db_entry if need
	mospf_db_entry_t *entry;
	int find = 0;
	int update = 0;
	list_for_each_entry(entry, &mospf_db, list)
	{
		if (entry->rid == ntohl(mospf->rid))
		{
			if (entry->seq < ntohs(lsu->seq))
			{
				entry->nadv = ntohl(lsu->nadv);
				entry->seq = ntohs(lsu->seq);
				entry->array = malloc(entry->nadv * MOSPF_LSA_SIZE);
				memcpy(entry->array, (char *)lsu + MOSPF_LSU_SIZE, entry->nadv * MOSPF_LSA_SIZE);
				entry->alive = MOSPF_DATABASE_TIMEOUT;
				update = 1;
			}
			find = 1;
		}
	}
	// if (update == 0 && find ==1) {
	// 	printf("receive a smaller or equal seq packet, do not forward\n");
	// 	pthread_mutex_unlock(&mospf_lock);
	// 	return;
	// }
	// if no match, insert a new entry
	if (!find)
	{
		mospf_db_entry_t *entry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
		entry->rid = ntohl(mospf->rid);
		entry->nadv = ntohl(lsu->nadv);
		entry->seq = ntohs(lsu->seq);
		entry->array = malloc(entry->nadv * MOSPF_LSA_SIZE);
		memcpy(entry->array, (char *)lsu + MOSPF_LSU_SIZE, entry->nadv * MOSPF_LSA_SIZE);
		entry->alive = MOSPF_DATABASE_TIMEOUT;
		list_add_tail(&entry->list, &mospf_db);
		update = 1;
	}

	// update rtable
	if (update)
	{
		// printf("[handle_mospf_lsu] database print\n");
		// print_database();
		update_rtable();
	}
	// forward this lsu packet
	if (--lsu->ttl > 0)
	{
		mospf->checksum = mospf_checksum(mospf);
		send_from_ifaces(packet, iface);
	}

	pthread_mutex_unlock(&mospf_lock);
}
void print_database()
{
	mospf_db_entry_t *entry;
	list_for_each_entry(entry, &mospf_db, list)
	{
		printf("    Rid %hhu.%hhu.%hhu.%hhu: has %d neighbors alive = %d\n", LE_IP_FMT_STR((entry->rid)), entry->nadv,entry->alive);
		int i;
		for (i = 0; i < entry->nadv; i++)
		{
			u32 ip = ntohl(entry->array[i].network);
			u32 rid = ntohl(entry->array[i].rid);
			printf("        Neighbor %d: rid = %hhu.%hhu.%hhu.%hhu, network = %hhu.%hhu.%hhu.%hhu\n", i, LE_IP_FMT_STR(rid), LE_IP_FMT_STR(ip));
		}
	}
}
int dist[10];
int visited[10];
int prev[10];
int Map[10][10];
u32 rids[10];
int V = 0;
int id2index(u32 rid)
{
	for (int i = 0; i < V; i++)
	{
		if (rids[i] == rid)
			return i;
	}
	rids[V] = rid;
	return V++;
}
int min_dist() {

	int minDist = INT_MAX;
	int chosen = -1;
	for (int i = 0; i < V; i++) {
		if (visited[i] == 0 && dist[i] < minDist) {
			chosen = i;
			minDist = dist[i];
		}
	}
	return chosen;
}
void update_rtable()
{
	// printf("in update_rtable\n");

	memset(Map, 0, 10 * 10 * 4);
	memset(dist, 0, 4 * 10);
	memset(prev, 0, 4 * 10);
	memset(visited, 0, 4 * 10);
	memset(rids, 0, 4 * 10);
	V = 0;

	// delete current entries
	rt_entry_t *rt_entry = NULL, *rt_entry_safe = NULL;
	list_for_each_entry_safe(rt_entry, rt_entry_safe, &rtable, list)
	{
		if (rt_entry->gw)
		{ // remaining local network route
			list_delete_entry(&rt_entry->list);
		}
	}
	// printf("finish delete\n");
	// ensure this router is source(index = 0);
	id2index(instance->router_id);
	// construct new graph
	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list)
	{
		for (int i = 0; i < db_entry->nadv; i++)
		{
			int source = id2index(db_entry->rid);
			if (ntohl(db_entry->array[i].rid))
			{
				int dest = id2index(ntohl(db_entry->array[i].rid));
				Map[source][dest] = 1;
				Map[dest][source] = 1;
			}
		}
	}
	// // printf("finish add node\n");
	// for (int i = 0; i < V; i++) {
	// 	for (int j = 0; j < V; j++) {
	// 		printf("%d",Map[i][j]);
	// 	}
	// 	printf("\n");
	// }

	// calculate shortest path
	for (int i = 0; i < V; i++)
	{
		dist[i] = INT_MAX;
		visited[i] = 0;
		prev[i] = -1;
	}
	dist[0] = 0;
	for (int i = 0; i < V; i++)
	{
		int u = min_dist();
		// printf("min_dist_node = %d\n",u);
		if (u == -1)
			return;
		visited[u] = 1;
		for (int v = 0; v < V; v++)
		{
			if (visited[v] == 0 && Map[u][v] == 1 && dist[u] + 1 < dist[v])
			{
				dist[v] = dist[u] + 1;
				prev[v] = u;
			}
		}
	}

	// construct rtable
	for (int now_dist = 1; now_dist < V; now_dist++)
	{
		for (int i = 0; i < V; i++)
		{
			if (dist[i] == now_dist)
			{
				int last, cur = i;
				while (cur != 0)
					last = cur, cur = prev[cur];

				// printf("%d %hhu.%hhu.%hhu.%hhu\n", last, LE_IP_FMT_STR(rids[last]));

				int flag = 0;
				iface_info_t *iface = NULL;
				mospf_nbr_t *nbr = NULL;
				list_for_each_entry(iface, &instance->iface_list, list)
				{
					list_for_each_entry(nbr, &iface->nbr_list, list)
					{
						if (nbr->nbr_id == rids[last])
						{
							flag = 1;
							break;
						}
					}
					if (flag)
						break;
				}
				if (!flag) return;

				iface_info_t *rt_iface = iface;
				u32 rt_gw = nbr->nbr_ip;

				// create rt entry
				mospf_db_entry_t *entry = NULL;
				list_for_each_entry(entry, &mospf_db, list)
				{
					if (entry->rid == rids[i])
					{
						for (int j = 0; j < entry->nadv; j++)
						{
							struct mospf_lsa *lsa = &entry->array[j];
							if (longest_prefix_match(ntohl(lsa->network)))
								continue;
							rt_entry_t *new_entry = new_rt_entry(ntohl(lsa->network), ntohl(lsa->mask), rt_gw, rt_iface);
							add_rt_entry(new_entry);
						}
					}
				}
			}
		}
	}
	// printf("successfully updated rtable\n");
	// print_rtable();
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION)
	{
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return;
	}
	if (mospf->checksum != mospf_checksum(mospf))
	{
		log(ERROR, "received mospf packet with incorrect checksum");
		return;
	}
	if (ntohl(mospf->aid) != instance->area_id)
	{
		log(ERROR, "received mospf packet with incorrect area id");
		return;
	}

	switch (mospf->type)
	{
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
