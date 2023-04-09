#include "queue.h"
#include "lib.h"
#include "list.h"
#include "protocols.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Routing table */
struct route_table_entry rtable[100000];
int rtable_len;

/* ARP table */
struct arp_entry *arp_table;
int arp_table_len;

/* ARP cache */
struct arp_entry arp_cache[100];
int arp_cache_size;

queue q;

struct route_table_entry *get_best_route(struct in_addr daddr) {
    int index = -1;	

    for (int i = 0; i < rtable_len; i++) {
        if ((daddr.s_addr & rtable[i].mask) == rtable[i].prefix) {
			if (index == -1 || ntohl(rtable[index].mask) < ntohl(rtable[i].mask)) {
				index = i;
			}
		}
    }
    if (index != -1) {
        return &rtable[index];
	}
	return NULL;
}

void swap_addresses(uint8_t *saddr, uint8_t *daddr) {

	//Swap addresses
	char *aux[6];
	memcpy(aux, saddr, 6 * sizeof(char));
	memcpy(saddr, daddr, 6 * sizeof(char));
	memcpy(daddr, aux, 6 * sizeof(char));
}

struct arp_header *swap_addresses32(struct arp_header *arp_hdr) {

	//Swap addresses
	uint32_t aux;
	aux = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = aux;

	return arp_hdr;
}


void icmp(packet *m, int type) {

	//Rextract the ethernet header from our packet
	struct ether_header *eth_hdr = (struct ether_header*)malloc
		(sizeof(struct ether_header));
	memcpy(eth_hdr, m->payload, sizeof(struct ether_header));

	//Set it to IPV4
	eth_hdr->ether_type = htons(0x0800);

	//Swap the addresses
	swap_addresses(eth_hdr->ether_shost, eth_hdr->ether_dhost);

	//Make a new packet to send back
	packet *new_packet = (packet*)malloc(sizeof(packet));

	//Initialize all the fields accordingly
	new_packet->interface = m->interface;
	new_packet->len = sizeof(struct ether_header) + sizeof(struct iphdr)
		+ sizeof(struct icmphdr) + 64;
	memcpy(new_packet->payload, eth_hdr, sizeof(struct ether_header));

	//Make the new ip header & initialize all the required fields
	struct iphdr *ip_hdr = (struct iphdr*)malloc(sizeof(struct iphdr));
	memcpy(ip_hdr, m->payload + sizeof(struct ether_header), sizeof(struct iphdr));

	//Set the source address
	int32_t aux = inet_addr(get_interface_ip(m->interface));
	ip_hdr->saddr = aux;

	//Set the destination address
	struct iphdr *old_ip_hdr = (struct iphdr*)(m->payload 
		+ sizeof(struct ether_header));
	ip_hdr->daddr = old_ip_hdr->saddr;

	//Default
	ip_hdr->protocol = 1;
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = sizeof(ip_hdr->tot_len) + sizeof(struct iphdr) + 64;

	memcpy(new_packet->payload + sizeof(struct ether_header), ip_hdr, 
		sizeof(struct iphdr));

	//Make the icmp header
	struct icmphdr *icmp_hdr = (struct icmphdr*)malloc(sizeof(struct icmphdr));

	// Case for Echo Reply
	if(type == 0) {
		memcpy(icmp_hdr, m->payload + sizeof(struct ether_header) 
			+ sizeof(struct iphdr), sizeof(struct icmphdr));
	}

	//Default
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr)));

	memcpy(new_packet->payload + sizeof(struct ether_header) + 
		sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
	memcpy(ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr), 
		old_ip_hdr + sizeof(struct iphdr), 64);

	send_to_link(new_packet->interface, new_packet->payload, new_packet->len);
}


void arp_request(struct route_table_entry *route) {
	packet request;

	request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	request.interface = route->interface;

	//Make a new ethernet header
	struct ether_header* eth_hdr = (struct ether_header*)malloc(sizeof
		(struct ether_header));
	uint8_t *dest = (uint8_t*)malloc(6 * sizeof(uint8_t));

	//Set for broadcast
	for(int i = 0; i < 6; i++) {
		dest[i] = 0xFF;
	}
	memcpy(eth_hdr->ether_dhost, dest, 6 * sizeof(uint8_t));

	//Set the source MAC address
	get_interface_mac(route->interface, eth_hdr->ether_shost);
	
	//Set as ARP
	eth_hdr->ether_type = htons(0x0806);

	//Make the arp header
	struct arp_header *arp_hdr = (struct arp_header*)malloc(sizeof
		(struct arp_header));
	
	//Default
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(2048);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);

	//Set the MAC for the sender
	get_interface_mac(route->interface, arp_hdr->sha);

	//Set the IP for the sender
	uint32_t aux = inet_addr(get_interface_ip(route->interface));
	arp_hdr->spa = aux;

	//Broadcasting
	memcpy(arp_hdr->tha, dest, 6 * sizeof(uint8_t));

	//Set the target IP
	arp_hdr->tpa = route->next_hop;

	memcpy(request.payload, eth_hdr, sizeof(struct ether_header));
	memcpy(request.payload + sizeof(struct ether_header), arp_hdr, 
		sizeof(struct arp_header));

	send_to_link(request.interface, request.payload, request.len);
}


void ip(packet m) {
	//Extract the ethernet header
	struct ether_header *eth_hdr = (struct ether_header *) m.payload;

	//Make the IP header
	struct iphdr *ip_hdr = ((void *) eth_hdr) + sizeof(struct ether_header);

	uint32_t aux = inet_addr(get_interface_ip(m.interface));

	//Echo
	if(aux == ip_hdr->daddr) {
		if(ip_hdr->protocol == 1) {
			struct icmphdr *icmp_hdr = (struct icmphdr*)(m.payload + 
				sizeof(struct ether_header) + sizeof(struct iphdr));
			if(icmp_hdr->type == 8) {
				printf("Echo request.\n");
				icmp(&m, 0);
				return;
			}
		}
	}

	//Check if the checksum is correct
	uint16_t my_check = ntohs(ip_hdr->check);
	ip_hdr->check = htons(0);
	if (checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)) != my_check) {
		printf("Wrong checksum. Dropping packet.\n");
		return;
	}

	//If ttl is 0 or 1, drop the packet
	if (ip_hdr->ttl <= 1) {
		printf("TTL 1 or less. Dropping packet.\n");
		icmp(&m, 11);
		return;
	}

	struct in_addr dest_ip;
	dest_ip.s_addr = ip_hdr->daddr;

	//Find the best route
	struct route_table_entry *route = get_best_route(dest_ip);
	if (route == NULL) {
		printf("Destination unreachalbe.\n");
		icmp(&m, 3);
		return;
	}

	//Search the arp table
	struct arp_entry *arp = NULL;
	for(int i = 0; i < arp_cache_size; i++) {
		if(route->next_hop == arp_cache[i].ip) {
			arp = &arp_cache[i];
			break;
		}
	}

	//If there's no entry in the arp table, generate a request & put the packet
	//in queue
	if (arp == NULL) {
		printf("ARP Request.\n");
		packet *temp = (packet*)malloc(sizeof(packet));
		memcpy(temp, &m, sizeof(packet));
		queue_enq(q, temp);
		arp_request(route);
		return;
	}

	//Update TTL and checksum
	ip_hdr->ttl--;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	//Update the destination MAC address
	memcpy(eth_hdr->ether_dhost, arp->mac, 6);

	//Update the source MAC address, by getting the address of the 
	//best route interface;
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	//Set packet's interface as the best route's interface
	m.interface = route->interface;

	send_to_link(m.interface, m.payload, m.len);
}


void arp(packet m) {
	//Extract the ethernet header
	struct ether_header *eth_hdr = (struct ether_header *) m.payload;

	//Make the ARP header
	struct arp_header *arp_hdr = ((void *) eth_hdr) + sizeof(struct ether_header);

	//ARP Request
	if(ntohs(arp_hdr->op) == 1) {
		printf("ARP request.\n");

		uint32_t aux = inet_addr(get_interface_ip(m.interface));

		if( aux == arp_hdr->tpa ) {
			arp_hdr->op = htons(2);

			//Swap addresses
			arp_hdr = swap_addresses32(arp_hdr);

			memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(uint8_t)*6);

			get_interface_mac(m.interface, arp_hdr->sha);

			//Update the destination MAC address
			memcpy(eth_hdr->ether_dhost, arp_hdr->tha, 6);

			//Update the source MAC address, by getting the address of the 
			//best route interface
			get_interface_mac(m.interface, eth_hdr->ether_shost);
		}
		send_to_link(m.interface, m.payload, m.len);
	}
	//ARP reply
	else {
		printf("ARP reply.\n");
		struct arp_entry* entry = (struct arp_entry*)malloc
			(sizeof(struct arp_entry));
		memcpy(entry->mac, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
		entry->ip = arp_hdr->spa;

		memcpy(&arp_cache[arp_cache_size], entry, sizeof(struct arp_entry));
		arp_cache_size++;

		while(queue_empty(q) == 0) {
			packet *p = (packet*)malloc(sizeof(packet));
			p = (packet*)queue_deq(q);

			//Extract the ethernet header
			struct ether_header *packet_eth = (struct ether_header*)p->payload;

			//Make the IP header
			struct iphdr *packet_iph = ((void *) packet_eth) 
				+ sizeof(struct ether_header);

			struct in_addr dest_ip;
			dest_ip.s_addr = packet_iph->daddr;

			//Get best route
			struct route_table_entry *route = get_best_route(dest_ip);

			//Check the arp table
			struct arp_entry *arp = NULL;
			for(int i = 0; i < arp_cache_size; i++) {
				if(route->next_hop == arp_cache[i].ip) {
					arp = &arp_cache[i];
					break;
				}
			}

			packet_iph->ttl--;
			packet_iph->check = 0;
			packet_iph->check = checksum((uint16_t *) packet_iph, 
				sizeof(struct iphdr));

			memcpy(packet_eth->ether_dhost, arp->mac, 6 * sizeof(uint8_t));
			p->interface = route->interface;

			send_to_link(p->interface, p->payload, p->len);
		}
	}
}


int main(int argc, char *argv[])
{

	char buf[MAX_PACKET_LEN];
	packet m;
	arp_cache_size = 0;

	rtable_len =  read_rtable(argv[1], rtable);

	q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");


		// I am using a packet to encapsulate the 3 fields into one. This is
		// going to be easier when working with the queue for the arp protocol
		memcpy(m.payload, buf, sizeof(buf));
		m.len = len;
		m.interface = interface;

		//Extract the ethernet header from the packet
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


		if(ntohs(eth_hdr->ether_type) == 0x0800) {
			ip(m);
			
		} else if(ntohs(eth_hdr->ether_type) == 0x0806) {
			arp(m);
		}
	}
}