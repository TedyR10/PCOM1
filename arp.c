#include "queue.h"
#include "arp.h"
#include "ip.h"
#include "lib.h"
#include "list.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

void arp_request(struct route_table_entry *route) {
	packet request;

	request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	request.interface = route->interface;

	struct ether_header* eth_header = (struct ether_header*)malloc(sizeof
		(struct ether_header));
	uint8_t *dest = (uint8_t*)malloc(6 * sizeof(uint8_t));
	for(int i = 0; i < 6; i++) {
		dest[i] = 0xFF;
	}
	memcpy(eth_header->ether_dhost, dest, 6 * sizeof(uint8_t));

	get_interface_mac(route->interface, eth_header->ether_shost);
	
	eth_header->ether_type = htons(0x0806);

	struct arp_header *arph = (struct arp_header*)malloc(sizeof
		(struct arp_header));
	arph->htype = htons(1);
	arph->ptype = htons(2048);
	arph->hlen = 6;
	arph->plen = 4;
	arph->op = htons(1);

	get_interface_mac(route->interface, arph->sha);

	struct in_addr* aux = (struct in_addr*)malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(route->interface), aux);
	arph->spa = aux->s_addr;

	memcpy(arph->tha, dest, 6 * sizeof(uint8_t));

	arph->tpa = route->next_hop;

	memcpy(request.payload, eth_header, sizeof(struct ether_header));
	memcpy(request.payload + sizeof(struct ether_header), arph, 
		sizeof(struct arp_header));

	send_to_link(request.interface, request.payload, request.len);
}


void arppacket(packet m, struct arp_entry *arp_cache,
	int arp_cache_size, queue q, struct route_table_entry *rtable,
	int rtable_len) {
	//Extract the payload from the packet
	struct ether_header *eth = (struct ether_header *) m.payload;

	// Start of IVP4 header
	struct arp_header *arph = ((void *) eth) + sizeof(struct ether_header);

	//ARP reply
	if(ntohs(arph->op) == 2) {
		struct arp_entry* to_insert = (struct arp_entry*)malloc
			(sizeof(struct arp_entry));
		memcpy(to_insert->mac, eth->ether_shost, 6 * sizeof(uint8_t));
		to_insert->ip = arph->spa;

		memcpy(&arp_cache[arp_cache_size], to_insert, sizeof(struct arp_entry));
		arp_cache_size++;

		while(queue_empty(q) == 0) {
			packet *p = (packet*)malloc(sizeof(packet));
			p = (packet*)queue_deq(q);

			//Extract the payload from the packet
			struct ether_header *packet_eth = (struct ether_header*)p->payload;

			// Start of IVP4 header
			struct iphdr *packet_iph = ((void *) packet_eth) 
				+ sizeof(struct ether_header);

			struct in_addr dest_ip;
			dest_ip.s_addr = packet_iph->daddr;

			//Find best matching route
			struct route_table_entry *route = get_best_route(dest_ip, rtable,
			rtable_len);

			struct arp_entry *arp = NULL;
			for(int i = 0; i < arp_cache_size; i++) {
				if(route->next_hop == arp_cache[i].ip) {
					arp = &arp_cache[i];
					break;
				}
			}

			packet_iph->ttl--;
			packet_iph->check = 0;
			packet_iph->check = checksum((void *) packet_iph, 
				sizeof(struct iphdr));

			memcpy(packet_eth->ether_dhost, arp->mac, 6 * sizeof(uint8_t));
			p->interface = route->interface;

			send_to_link(p->interface, p->payload, p->len);
		}
	// ARP Request
	} else if(ntohs(arph->op) == 1) {;
		struct in_addr* aux = (struct in_addr*)malloc(sizeof(struct in_addr));
		inet_aton(get_interface_ip(m.interface), aux);

		if( aux->s_addr == arph->tpa ) {
			arph->op = htons(2);

			uint32_t aux;
			aux = arph->spa;
			arph->spa = arph->tpa;
			arph->tpa = aux;

			memcpy(arph->tha, arph->sha, sizeof(uint8_t)*6);

			get_interface_mac(m.interface, arph->sha);

			//Update the destination MAC address
			memcpy(eth->ether_dhost, arph->tha, 6);

			//Update the source MAC address, by getting the address of the 
			//best route interface
			get_interface_mac(m.interface, eth->ether_shost);
		}
		send_to_link(m.interface, m.payload, m.len);
	}
}