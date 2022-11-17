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
#define INTERNAL 0
#define EXTERNAL 1
// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	// fprintf(stdout, "TODO: determine the direction of this packet.\n");

	struct iphdr *ip = packet_to_ip_hdr(packet);
	rt_entry_t * daddr_rt = longest_prefix_match(ntohl(ip->daddr));
	rt_entry_t * saddr_rt = longest_prefix_match(ntohl(ip->saddr));
	
	int daddrPos,saddrPos;
	if (daddr_rt->iface == nat.external_iface) daddrPos = EXTERNAL;
	else if (daddr_rt->iface == nat.internal_iface) daddrPos = INTERNAL;
	if (saddr_rt->iface == nat.external_iface) saddrPos = EXTERNAL;
	else if (saddr_rt->iface == nat.internal_iface) saddrPos = INTERNAL;

	if (saddrPos == EXTERNAL && ntohl(ip->daddr) == nat.external_iface->ip) return DIR_IN;
	if (saddrPos == INTERNAL && daddrPos == EXTERNAL) return DIR_OUT;
	return DIR_INVALID;
}
struct nat_mapping* traverse_hash_list(struct list_head* head, u32 ip,u16 port,int dir)
{
	struct nat_mapping *map = NULL;
	list_for_each_entry(map,head,list){
		if(dir == DIR_IN){
			if(ip == map->external_ip && port == map->external_port)
			return map;
		}else{
			if(ip == map->internal_ip && port == map->internal_port)
			return map;
		}
	}
	return NULL;
}
u16 assign_external_port(iface_info_t *iface, char *packet, int len){
	u16 new_port = 0, i;
	for (i = NAT_PORT_MIN; i <= NAT_PORT_MAX; i++) {
		if (!nat.assigned_ports[i]) {
			nat.assigned_ports[i] = 1;
			new_port = i;
			return new_port;
		}
	}

	// 	icmp_send_packet(packet, len, iface, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
	// 	pthread_mutex_unlock(&nat.lock);
	// 	return;
	return 0;
}
struct dnat_rule* find_rule(uint32_t external_ip,uint16_t external_port) {
	struct dnat_rule *rule;
	list_for_each_entry(rule, &nat.rules, list) {
		if (rule->external_ip == external_ip && rule->external_port == external_port) {
			return rule;
		}
	}
	return NULL;
}
// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");

	pthread_mutex_lock(&nat.lock);
	
	struct iphdr* ip = packet_to_ip_hdr(packet);
	struct tcphdr* tcp = packet_to_tcp_hdr(packet);
	u32 saddr = ntohl(ip->saddr);
	u32 daddr = ntohl(ip->daddr);
	// fprintf(stdout, "packet saddr is "IP_FMT".\n", HOST_IP_FMT_STR(saddr));
	// fprintf(stdout, "packet daddr is "IP_FMT".\n", HOST_IP_FMT_STR(daddr));
	//get map key
	char* buf = malloc(4);
	u32 origin_key = (dir == DIR_IN)? (ntohl(ip->saddr)+ntohs(tcp->sport)):
				(ntohl(ip->daddr)+ntohs(tcp->dport));
	memcpy(buf, &origin_key,4);
	u8 key = hash8(buf, 4);
	// printf("origin_key = %d, key = %d\n",origin_key,key);
	//get map entry
	struct list_head* head = &nat.nat_mapping_list[key];
	// if (head) printf("nat.nat_mappping_list[key] is not empty\n");
	// else printf("nat.nat_mappping_list[key] is empty\n");
	struct nat_mapping* map_entry = NULL;
	if(dir == DIR_IN){
		map_entry = traverse_hash_list(head,ntohl(ip->daddr),ntohs(tcp->dport),DIR_IN);
	}else{
		map_entry = traverse_hash_list(head,ntohl(ip->saddr),ntohs(tcp->sport),DIR_OUT);
	}
	// if (map_entry) printf("find a no empty map entry\n");
	// else printf("could not find a corret map entry\n");
	if (!map_entry) {
		map_entry = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));
		if(dir == DIR_IN) {
			map_entry->remote_ip = ntohl(ip->saddr);
			map_entry->remote_port = ntohs(tcp->sport);
			map_entry->external_ip = ntohl(ip->daddr);
			map_entry->external_port = ntohs(tcp->dport);

			struct dnat_rule* rule = find_rule(map_entry->external_ip,map_entry->external_port);
			if(rule == NULL){
				printf("no match rule!\n");
				pthread_mutex_unlock(&nat.lock);
				return;
			}
			map_entry->internal_ip = rule->internal_ip;
			map_entry->internal_port = rule->internal_port;

		}else{
			map_entry->internal_ip = ntohl(ip->saddr);
			map_entry->internal_port = ntohs(tcp->sport);
			map_entry->remote_ip = ntohl(ip->daddr);
			map_entry->remote_port = ntohs(tcp->dport);

			map_entry->external_ip = nat.external_iface->ip;
			map_entry->external_port = assign_external_port(iface, packet, len);
			if(map_entry->external_port == 0){
				printf("run out of port!\n");
				pthread_mutex_unlock(&nat.lock);
				return;
			}
		}
		memset(&map_entry->conn,0,sizeof(struct nat_connection));
 		list_add_tail(&map_entry->list,head);
		// printf("create a new map enrty\n");
	}

	//update conn
	if(dir == DIR_IN){
		map_entry->conn.external_ack = ntohl(tcp->ack);
		map_entry->conn.external_fin = tcp->flags == TCP_FIN? 1:0;
		map_entry->conn.external_seq_end = ntohl(tcp->seq);
	}else if(dir == DIR_OUT){
		map_entry->conn.internal_ack = ntohl(tcp->ack);
		map_entry->conn.internal_fin = tcp->flags == TCP_FIN? 1:0;
		map_entry->conn.internal_seq_end = ntohl(tcp->seq);
	}else{
		pthread_mutex_unlock(&nat.lock);
		return;
	}
	time(&map_entry->update_time);


	//translate
	if(dir == DIR_IN){
		ip->daddr = htonl(map_entry->internal_ip);
		tcp->dport = htons(map_entry->internal_port);
	}else{
		ip->saddr = htonl(map_entry->external_ip);
		tcp->sport = htons(map_entry->external_port);
	}
	ip->checksum = ip_checksum(ip);
	tcp->checksum = tcp_checksum(ip,tcp);

	//resend
	// printf("send packet by arp\n");
	if(dir == DIR_IN){
		pthread_mutex_unlock(&nat.lock);
		iface_send_packet_by_arp(nat.internal_iface,ntohl(ip->daddr),packet,len);
	}else{
		pthread_mutex_unlock(&nat.lock);
		iface_send_packet_by_arp(nat.external_iface,ntohl(ip->daddr),packet,len);
	}

}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	// if (dir == 1) printf("\ndir = DIR_IN\n");//1 DIR_IN 2 DIR_OUT
	// if (dir == 2) printf("\ndir = DIR_OUT\n");
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
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
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);
		time_t cur;
		time(&cur);
		pthread_mutex_lock(&nat.lock);
		for(int i = 0;i<HASH_8BITS;i++){
			struct nat_mapping *map = NULL, *map_safe = NULL;
			list_for_each_entry_safe(map,map_safe, &nat.nat_mapping_list[i],list){
				if (cur - map->update_time >= TCP_ESTABLISHED_TIMEOUT || is_flow_finished(&map->conn)) {
					nat.assigned_ports[map->external_port] = 0;	
					printf("delet a map entry");
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
	// fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
	pthread_mutex_lock(&nat.lock);
	
	FILE* fd = fopen(filename,"r");

	//read context
	char file[200];
	int tail = fread(file,1,200,fd);
	file[tail] = '\0';

	//read iface name
	char name[8];
	name[7] = '\0';
	//ignore internal-iface:
	int i = 0;
	while(file[i++]!=' ');
	
	//set internal iface
	memcpy(name,&file[i],7);
	nat.internal_iface = if_name_to_iface(name);
	while(file[i++]!='\n');
	
	//ignore external-iface: 
	while(file[i++]!=' ');
	
	//set external iface
	memcpy(name,&file[i],7);
	nat.external_iface = if_name_to_iface(name);
	while(file[i++]!='\n');

	while(file[i] != '\0') {
		while(file[i]!=' ' && file[i] != '\0') i++;
		if (file[i] == '\0') {
			break;
		}
		i++;
		struct dnat_rule *rule = (struct dnat_rule *) malloc(sizeof(struct dnat_rule));
		u32 ip = 0, tmp = 0; 
		u16 port = 0;
		int len;
		// get ip
		for (; file[i] != ':'; i++) {
			if (file[i] >= '0' && file[i] <= '9') tmp = tmp * 10 + file[i] - '0';
			else if (file[i] == '.') ip = (ip << 8) + tmp, tmp = 0;
		}
		ip = (ip << 8) + tmp;
		i++;
		//get port
		for (; file[i] != ' '; i++)
			port = port * 10 + file[i] - '0';
		
		rule->external_ip = ip;
		rule->external_port = port;
		i += 4;

		port = 0;tmp = 0; ip = 0;
		// get ip
		for (; file[i] != ':'; i++) {
			if (file[i] >= '0' && file[i] <= '9') tmp = tmp * 10 + file[i] - '0';
			else if (file[i] == '.') ip = (ip << 8) + tmp, tmp = 0;
		}
		ip = (ip << 8) + tmp;
		i++;
		//get port
		for (; file[i] != '\n' && file[i] != '\0'; i++)
			port = port * 10 + file[i] - '0';
		rule->internal_ip = ip;
		rule->internal_port = port;
		list_add_tail(&rule->list, &nat.rules);
	}
	// u32 nat_ex_ip = nat.external_iface->ip;
	// u32 nat_in_ip = nat.internal_iface->ip;
	// printf("nat.external_ip = %hhu.%hhu.%hhu.%hhu, nat.internal_ip = %hhu.%hhu.%hhu.%hhu\n",LE_IP_FMT_STR(nat_ex_ip),LE_IP_FMT_STR(nat_in_ip));
	// struct dnat_rule *rule = NULL;
	// list_for_each_entry(rule, &nat.rules, list) {
	// 	u32 rule_ex_ip = rule->external_ip;
	// 	u32 rule_in_ip = rule->internal_ip;
	// 	printf("rule->external_ip = %hhu.%hhu.%hhu.%hhu, rule->external_port = %d\n",LE_IP_FMT_STR(rule_ex_ip),rule->external_port);
	// 	printf("rule->internal_ip = %hhu.%hhu.%hhu.%hhu, rule->internal_port = %d\n",LE_IP_FMT_STR(rule_in_ip),rule->internal_port);
	// }

	pthread_mutex_unlock(&nat.lock);
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
