#ifndef ARP_H
#define ARP_H
#include "queue.h"
#include "lib.h"

void arppacket(packet m, struct arp_entry *arp_cache,
	int arp_cache_size, queue q, struct route_table_entry *rtable,
	int rtable_len);

void arp_request(struct route_table_entry *route);

#endif