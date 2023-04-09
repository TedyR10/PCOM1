#include "queue.h"
#include "icmp.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

void icmp(packet *m, int type) {
	packet *to_send = (packet*)malloc(sizeof(packet));

	//PACKET
	to_send->interface = m->interface;
	to_send->len = sizeof(struct ether_header) + sizeof(struct iphdr)
		+ sizeof(struct icmphdr) + 64;

	//ETHER HEADER
	struct ether_header *eth = (struct ether_header*)malloc
		(sizeof(struct ether_header));
	memcpy(eth, m->payload, sizeof(struct ether_header));

	//Swap addresses
	char *aux_mac = (char*)malloc(6 * sizeof(char));
	memcpy(aux_mac, eth->ether_shost, 6 * sizeof(char));
	memcpy(eth->ether_shost, eth->ether_dhost, 6 * sizeof(char));
	memcpy(eth->ether_dhost, aux_mac, 6 * sizeof(char));

	//IPv4 type
	eth->ether_type = htons(0x0800);

	memcpy(to_send->payload, eth, sizeof(struct ether_header));

	//IP HEADER
	struct iphdr *iph = (struct iphdr*)malloc(sizeof(struct iphdr));
	memcpy(iph, m->payload + sizeof(struct ether_header), sizeof(struct iphdr));

	struct in_addr* aux_ip = (struct in_addr*)malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(m->interface), aux_ip);
	iph->saddr = aux_ip->s_addr;

	struct iphdr *received_iph = (struct iphdr*)(m->payload 
		+ sizeof(struct ether_header));
	iph->daddr = received_iph->saddr;

	iph->protocol = 1;
	iph->ttl = 64;
	iph->tot_len += sizeof(struct iphdr) + 64;

	memcpy(to_send->payload + sizeof(struct ether_header), iph, 
		sizeof(struct iphdr));

	//ICMP HEADER
	struct icmphdr *icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));
	if(type == 0) {
		memcpy(icmph, m->payload + sizeof(struct ether_header) 
			+ sizeof(struct iphdr), sizeof(struct icmphdr));
	}
	icmph->type = type;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->checksum = checksum((void*)icmph, sizeof(struct icmphdr));

	memcpy(to_send->payload + sizeof(struct ether_header) + 
		sizeof(struct iphdr), icmph, sizeof(struct icmphdr));
	memcpy(iph + sizeof(struct iphdr) + sizeof(struct icmphdr), 
		received_iph + sizeof(struct iphdr), 64);

	send_to_link(to_send->interface, to_send->payload, to_send->len);
}