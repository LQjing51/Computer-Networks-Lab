#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"
#include "arp.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

static int check_private_addr(u32 ip) {
	//10.0.0.0/8
	if ((ip & 0xff000000) == 0x0a000000) return 1;
	//172.16.0.0/12
	if ((ip & 0xfff00000) == 0xac100000) return 1;
	//192.168.0.0/16
	if ((ip & 0xffff0000) == 0xc0a80000) return 1;
	return 0;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	struct iphdr *iphdr = packet_to_ip_hdr(packet);

	if (check_private_addr(ntohl(iphdr->saddr)) && !check_private_addr(ntohl(iphdr->daddr)))
		return DIR_OUT;

	if (!check_private_addr(ntohl(iphdr->saddr)) && ntohl(iphdr->daddr) == nat.external_iface->ip)
		return DIR_IN;
	
	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	pthread_mutex_lock(&nat.lock);
	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	struct tcphdr *tcphdr = packet_to_tcp_hdr(packet);

	// printf("recv packet, dir = %d\n", dir);

	// get hash
	u32 *buf = malloc(8);
	if (dir == DIR_IN) buf[0] = ntohl(iphdr->saddr), buf[1] = ntohs(tcphdr->sport);
	else buf[0] = ntohl(iphdr->daddr), buf[1] = ntohs(tcphdr->dport);
	u8 hash = hash8((char *) buf, 8);

	// printf("hash = %d\n", (int) hash);

	struct nat_mapping *map = NULL;
	if (dir == DIR_IN) {
		struct nat_mapping *entry;
		list_for_each_entry(entry, &nat.nat_mapping_list[hash], list) {
			if (entry->external_ip == ntohl(iphdr->daddr) && entry->external_port == ntohs(tcphdr->dport)) {
				map = entry;
				break;
			}
		}
	} else {
		struct nat_mapping *entry;
		list_for_each_entry(entry, &nat.nat_mapping_list[hash], list) {
			if (entry->internal_ip == ntohl(iphdr->saddr) && entry->internal_port == ntohs(tcphdr->sport)) {
				map = entry;
				break;
			}
		}
	}

	// check if we need to create a new mapping structure
	if (!map) {

		// printf("allocate a new mapping\n");

		map = (struct nat_mapping *) malloc(sizeof(struct nat_mapping));
		if (dir == DIR_IN) {
			// find rule
			int flag = 0;
			struct dnat_rule *rule;
			list_for_each_entry(rule, &nat.rules, list) {
				if (rule->external_ip == ntohl(iphdr->daddr) && rule->external_port == ntohs(tcphdr->dport)) {
					flag = 1;
					break;
				}
			}
			if (!flag) {
				// cannot find rule
				icmp_send_packet(packet, len, iface, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
				free(packet);
				pthread_mutex_unlock(&nat.lock);
				return;
			}
			map->remote_ip = ntohl(iphdr->saddr);
			map->remote_port = ntohs(tcphdr->sport);
			map->external_ip = ntohl(iphdr->daddr);
			map->external_port = ntohs(tcphdr->dport);
			map->internal_ip = rule->internal_ip;
			map->internal_port = rule->internal_port;
		} else {
			// find an available port
			u16 new_port = 0, i;
			for (i = NAT_PORT_MIN; i <= NAT_PORT_MAX; i++) {
				if (!nat.assigned_ports[i]) {
					nat.assigned_ports[i] = 1;
					new_port = i;
					break;
				}
			}
			if (!new_port) {
				// cannot assign new port
				icmp_send_packet(packet, len, iface, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
				free(packet);
				pthread_mutex_unlock(&nat.lock);
				return;
			}
			map->remote_ip = ntohl(iphdr->daddr);
			map->remote_port = ntohs(tcphdr->dport);
			map->internal_ip = ntohl(iphdr->saddr);
			map->internal_port = ntohs(tcphdr->sport);
			map->external_ip = nat.external_iface->ip;
			map->external_port = new_port;
		}
		time(&map->update_time);
		memset(&map->conn, 0, sizeof(struct nat_connection));
		list_add_head(&map->list, &nat.nat_mapping_list[hash]);
	} else {
		time(&map->update_time);
	}

	// update connection state
	if (dir == DIR_IN) {
		map->conn.external_seq_end = ntohl(tcphdr->seq);
		map->conn.external_ack = ntohl(tcphdr->ack);
		map->conn.external_fin = tcphdr->flags == TCP_FIN ? 1 : 0;
	} else {
		map->conn.internal_seq_end = ntohl(tcphdr->seq);
		map->conn.internal_ack = ntohl(tcphdr->ack);
		map->conn.internal_fin = tcphdr->flags == TCP_FIN ? 1 : 0;
	}

	// do translate
	if (dir == DIR_IN) {
		iphdr->daddr = htonl(map->internal_ip);
		tcphdr->dport = htons(map->internal_port);
	} else {
		iphdr->saddr = htonl(map->external_ip);
		tcphdr->sport = htons(map->external_port);
	}

	tcphdr->checksum = tcp_checksum(iphdr, tcphdr);
	iphdr->checksum = ip_checksum(iphdr);

	// send packet
	if (dir == DIR_IN) {
		iface_send_packet_by_arp(nat.internal_iface, ntohl(iphdr->daddr), packet, len);
	} else {
		iface_send_packet_by_arp(nat.external_iface, ntohl(iphdr->daddr), packet, len);
	}

	pthread_mutex_unlock(&nat.lock);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	// printf("in nat_translate_packet\n");

	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, iface, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		sleep(1);

		pthread_mutex_lock(&nat.lock);

		time_t cur;
		time(&cur);
		int i;
		for (i = 0; i < HASH_8BITS; i++) {
			struct nat_mapping *map, *map_;
			list_for_each_entry_safe(map, map_, &nat.nat_mapping_list[i], list) {
				if (cur - map->update_time >= TCP_ESTABLISHED_TIMEOUT || is_flow_finished(&map->conn)) {
					// delete this mapping
					nat.assigned_ports[map->external_port] = 0;	// for SNAT
					list_delete_entry(&map->list);
					free(map);
				}
			}
		}

		pthread_mutex_unlock(&nat.lock);
	}

	return NULL;
}

int parse_config(const char *filename)
{
	FILE *f = fopen(filename, "r");
	char s[50];

	while (~fscanf(f, "%s", s)) {
		if (s[0] == 'i' || s[0] == 'e') {
			char c = s[0];
			fscanf(f, "%s", s);
			iface_info_t *iface;
			int flag = 0;
			list_for_each_entry(iface, &instance->iface_list, list) {
				if (!strcmp(iface->name, s)) {
					flag = 1;
					break;
				}
			}
			if (!flag) printf("parse config error.\n");
			if (c == 'i')
				nat.internal_iface = iface;
			else
				nat.external_iface = iface;
		} else if (s[0] == 'd') {
			struct dnat_rule *rule = (struct dnat_rule *) malloc(sizeof(struct dnat_rule));
			fscanf(f, "%s", s);
			u32 ip, tmp; u16 port;
			int i, len;
			// get ip and port from s
			len = strlen(s);
			ip = port = tmp = 0;
			for (i = 0; s[i] != ':'; i++) {
				if (isdigit(s[i])) tmp = tmp * 10 + s[i] - '0';
				else if (s[i] == '.') ip = (ip << 8) + tmp, tmp = 0;
			}
			ip = (ip << 8) + tmp;
			for (; i < len; i++)
				if (isdigit(s[i])) port = port * 10 + s[i] - '0';
			rule->external_ip = ip;
			rule->external_port = port;
			fscanf(f, "%s", s);
			fscanf(f, "%s", s);
			// get ip and port from s (again)
			len = strlen(s);
			ip = port = tmp = 0;
			for (i = 0; s[i] != ':'; i++) {
				if (isdigit(s[i])) tmp = tmp * 10 + s[i] - '0';
				else if (s[i] == '.') ip = (ip << 8) + tmp, tmp = 0;
			}
			ip = (ip << 8) + tmp;
			for (; i < len; i++)
				if (isdigit(s[i])) port = port * 10 + s[i] - '0';
			rule->internal_ip = ip;
			rule->internal_port = port;
			// printf("ex:"IP_FMT":%d, in:"IP_FMT":%d\n", LE_IP_FMT_STR(rule->external_ip), (int) rule->external_port,\
			// LE_IP_FMT_STR(rule->internal_ip), (int) rule->internal_port);
			// insert new rule into rule table
			list_add_head(&rule->list, &nat.rules);
		} else {
			printf("parse config error.\n");
		}
	}

	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	fprintf(stdout, "TODO: release all resources allocated.\n");
}
