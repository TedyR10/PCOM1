#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "list.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


struct route_table_entry *get_best_route(struct in_addr dest_ip, struct route_table_entry *rtable,
	int rtable_len) {
    int index = -1;	

    for (int i = 0; i < rtable_len; i++) {
        if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {
			if (index == -1 || ntohl(rtable[index].mask) < ntohl(rtable[i].mask)) {
				index = i;
			}
		}
    }
    if (index != -1)
        return &rtable[index];
	return NULL;
}

void ippacket(packet m, struct arp_entry *arp_cache,
	int arp_cache_size, queue q, struct route_table_entry *rtable,
	int rtable_len) {
	//Extract the payload from the packet
	struct ether_header *eth = (struct ether_header *) m.payload;

	// Start of IVP4 header
	struct iphdr *iph = ((void *) eth) + sizeof(struct ether_header);

	struct in_addr* aux = (struct in_addr*)malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(m.interface), aux);

	//ICMP request case
	if(aux->s_addr == iph->daddr) {
		if(iph->protocol == 1) {
			struct icmphdr *icmph = (struct icmphdr*)(m.payload + 
				sizeof(struct ether_header) + sizeof(struct iphdr));
			if(icmph->type == 8) {
				icmp(&m, 0);
				return;
			}
		}
	}

	uint16_t my_check = ntohs(iph->check);
	iph->check = htons(0);

	// If checksum is wrong, throw the packet
	if (checksum((uint16_t*) iph, sizeof(struct iphdr)) != my_check) {
		return;
	}

	// If ttl is 0 or 1, throw the packet
	if (iph->ttl == 0 || iph->ttl == 1) {
		icmp(&m, 11);
		return;
	}

	struct in_addr dest_ip;
	dest_ip.s_addr = iph->daddr;

	//Find best matching route
	struct route_table_entry *route = get_best_route(dest_ip, rtable, rtable_len);
	if (route == NULL) {
		icmp(&m, 3);
		return;
	}

	struct arp_entry *arp = NULL;
	for(int i = 0; i < arp_cache_size; i++) {
		if(route->next_hop == arp_cache[i].ip) {
			arp = &arp_cache[i];
			break;
		}
	}
	if (arp == NULL) {
		packet *p = (packet*)malloc(sizeof(packet));
		memcpy(p, &m, sizeof(packet));
		queue_enq(q, p);
		arp_request(route);
		return;
	}
	//Update TTL and checksum
	iph->ttl--;
	iph->check = htons(checksum((uint16_t *)iph, sizeof(struct iphdr)));

	//Update the destination MAC address
	memcpy(eth->ether_dhost, arp->mac, 6);

	//Update the source MAC address, by getting the address of the 
	//best route interface;
	get_interface_mac(route->interface, eth->ether_shost);

	//Set packet's interface as the best route's interface
	m.interface = route->interface;

	send_to_link(m.interface, m.payload, m.len);
}
