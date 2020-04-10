#include "./include/router.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init();

	// route table
	std::vector<struct route_table_entry> r_table = parse_route_table();

	// arp table
	std::unordered_map<uint32_t, uint8_t*> arp_table;

	// unsent packets
	std::queue<std::pair<packet*, struct route_table_entry*>> packets;

	while (true) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// get ethernet header
		struct ether_header* eth_hdr = (struct ether_header*) m.payload;

		// ------------------------------------------------------> arp type
		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {

			// get arp header
			struct ether_arp* arp_hdr = (struct ether_arp*) (m.payload + sizeof(struct ether_header));

			// ------------------------------------------------------> arp reply type
			if (arp_hdr->ea_hdr.ar_op == htons(ARPOP_REPLY)) {
				resolve_arp_reply(m, eth_hdr, arp_hdr, arp_table, packets);
				continue;
			}

			// ------------------------------------------------------> arp request type
			if (arp_hdr->ea_hdr.ar_op == htons(ARPOP_REQUEST)) {
				resolve_arp_request(m, eth_hdr, arp_hdr);
				continue;
			}
		}

		// ------------------------------------------------------> ip type
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {

			// get ip and icmp headers
			struct iphdr* ip_hdr = (struct iphdr*) (m.payload + sizeof(struct ether_header));
			struct icmphdr* icmp_hdr = (struct icmphdr*) (m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			// check control sum
			uint16_t old_sum = ip_hdr->check;
			ip_hdr->check = 0;
			if (old_sum != checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}

			// check time to leave
			if (ip_hdr->ttl <= 1) {
				resolve_timeout(m, eth_hdr, ip_hdr, icmp_hdr);
				continue;
			}

			// ------------------------------------------------------> icmp request type
			if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))
				&& ip_hdr->protocol == IPPROTO_ICMP && icmp_hdr->type == ICMP_ECHO) {
				resolve_icmp_echo(m, eth_hdr, ip_hdr, icmp_hdr);
				continue;
			}

			// check if destination is unreachable
			struct route_table_entry* r_entry = get_best_route(r_table, ip_hdr->daddr);
			if (r_entry == NULL) {
				resolve_destination_unreachable(m, eth_hdr, ip_hdr, icmp_hdr);
				continue;
			}

			// check if arp_table contains next hop ip
			if (arp_table.find(r_entry->next_hop) == arp_table.end()) {
				resolve_no_arp_entry(m, eth_hdr, ip_hdr, icmp_hdr, packets, r_entry);
				continue;
			}

			// forward packet
			resolve_forwarding(m, eth_hdr, ip_hdr, icmp_hdr, arp_table, r_entry);
			continue;
		}
	}
}
