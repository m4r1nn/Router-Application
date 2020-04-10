#include "./include/router.h"

void resolve_arp_reply(packet& m, struct ether_header* eth_hdr, struct ether_arp* arp_hdr,
	std::unordered_map<uint32_t, uint8_t*>& arp_table, std::queue<std::pair<packet*, struct route_table_entry*>>& packets) {

	// get first packet from queue to add arp entry
	std::pair<packet*, struct route_table_entry*> copy = packets.back();
	struct route_table_entry* r_entry = copy.second;
	uint8_t wanted_mac[MAC_LEN];
	memcpy(wanted_mac, arp_hdr->arp_sha, MAC_LEN * sizeof(uint8_t));

	// add arp entry in table
	arp_table[r_entry->next_hop] = (uint8_t*) malloc(MAC_LEN * sizeof(uint8_t));
	memcpy(arp_table[r_entry->next_hop], arp_hdr->arp_sha, MAC_LEN * sizeof(uint8_t));

	// send remaining packets
	while (!packets.empty()) {

		// get packet with its next-hop
		copy = packets.front();
		packets.pop();
		m = (*copy.first);
		r_entry = copy.second;

		// get headers
		struct iphdr* ip_hdr = (struct iphdr*) (m.payload + sizeof(struct ether_header));
		struct icmphdr* icmp_hdr = (struct icmphdr*) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

		// prepare ethernet header
		get_interface_mac(m.interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, wanted_mac, MAC_LEN);

		// prepare ip and icmp headers
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = checksum(icmp_hdr, m.len - sizeof(struct ether_header) - sizeof(struct iphdr));

		// send packet
		send_packet(r_entry->interface, &m);
	}
}

void resolve_arp_request(packet& m, struct ether_header* eth_hdr, struct ether_arp* arp_hdr) {

	// set packet size
	m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

	// prepare ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN * sizeof(uint8_t));
	get_interface_mac(m.interface, eth_hdr->ether_shost);

	// prepare arp header
	memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, MAC_LEN * sizeof(uint8_t));
	get_interface_mac(m.interface, arp_hdr->arp_sha);
	std::swap(arp_hdr->arp_spa, arp_hdr->arp_tpa);
	arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);

	// send packet
	send_packet(m.interface, &m);
}

void resolve_timeout(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr) {

	// set packet size
	m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	// prepare ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN * sizeof(uint8_t));
	get_interface_mac(m.interface, eth_hdr->ether_shost);

	// prepare ip header
	std::swap(ip_hdr->saddr, ip_hdr->daddr);
	ip_hdr->ttl = DEFAULT_TTL;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	// prepare icmp header
	icmp_hdr->type = ICMP_TIMXCEED;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, m.len - sizeof(struct ether_header) - sizeof(struct iphdr));

	// send packet
	send_packet(m.interface, &m);	
}

void resolve_icmp_echo(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr) {

	// set packet size
	m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	// prepare ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN * sizeof(uint8_t));
	get_interface_mac(m.interface, eth_hdr->ether_shost);

	// prepare ip header
	std::swap(ip_hdr->saddr, ip_hdr->daddr);
	ip_hdr->ttl = DEFAULT_TTL;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	// prepare icmp header
	icmp_hdr->type = ICMP_ECHOREPLY;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, m.len - sizeof(struct ether_header) - sizeof(struct iphdr));

	// send packet
	send_packet(m.interface, &m);
}

void resolve_destination_unreachable(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr) {

	// set packet size
	m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	// prepare ethernet header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN * sizeof(uint8_t));
	get_interface_mac(m.interface, eth_hdr->ether_shost);

	// prepare ip header
	std::swap(ip_hdr->saddr, ip_hdr->daddr);
	ip_hdr->ttl = DEFAULT_TTL;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

	// prepare icmp header
	icmp_hdr->type = ICMP_DEST_UNREACH;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, m.len - sizeof(struct ether_header) - sizeof(struct iphdr));

	// send packet
	send_packet(m.interface, &m);
}

void resolve_no_arp_entry(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr,
	std::queue<std::pair<packet*, struct route_table_entry*>>& packets, struct route_table_entry* r_entry) {
	
	// store packet (with its next-hop) to send later
	packet* reserved = (packet*) malloc(sizeof(packet));
	memcpy(reserved, &m, sizeof(packet));
	std::pair<packet*, struct route_table_entry*> copy(reserved, r_entry);
	packets.push(copy);

	// set packet size
	m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

	// prepare ethernet header
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(m.interface, eth_hdr->ether_shost);
	memset(eth_hdr->ether_dhost, 0xff, MAC_LEN * sizeof(uint8_t));

	// get arp header
	struct ether_arp* arp_hdr = (struct ether_arp*) (m.payload + sizeof(struct ether_header));

	// prepare arp header
	memcpy(arp_hdr->arp_tpa, &ip_hdr->daddr, IP_LEN * sizeof(uint8_t));
	memcpy(arp_hdr->arp_spa, get_interface_ip(m.interface), IP_LEN * sizeof(uint8_t));
	memset(arp_hdr->arp_tha, 0x00, MAC_LEN * sizeof(uint8_t));
	get_interface_mac(r_entry->interface, arp_hdr->arp_sha);
	arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
	arp_hdr->ea_hdr.ar_pln = IP_LEN;
	arp_hdr->ea_hdr.ar_hln = MAC_LEN;
	arp_hdr->ea_hdr.ar_hrd = htons(1);
	arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);

	// send packet
	send_packet(r_entry->interface, &m);
}

void resolve_forwarding(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr,
	std::unordered_map<uint32_t, uint8_t*>& arp_table, struct route_table_entry* r_entry) {

	// prepare ehternet header
	get_interface_mac(m.interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_table[r_entry->next_hop], MAC_LEN * sizeof(uint8_t));

	// forward packet
	ip_hdr->ttl--;

	// recalculate checksums
	ip_hdr->check = 0;
	ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, m.len - sizeof(struct ether_header) - sizeof(struct iphdr));

	// send packet
	send_packet(r_entry->interface, &m);
}
