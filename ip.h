#ifndef IP_H
#define IP_H
#include "queue.h"
#include "protocols.h"
#include "lib.h"
#include <netinet/in.h>

void ippacket(packet m, struct arp_entry *arp_cache,
	int arp_cache_size, queue q, struct route_table_entry *rtable,
	int rtable_len);

struct route_table_entry *get_best_route(struct in_addr dest_ip, struct route_table_entry *rtable,
	int rtable_len);

#endif