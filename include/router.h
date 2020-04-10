#ifndef ROUTER_H_
#define ROUTER_H_

#include "skel.h"
#include "parser.h"

#define DEFAULT_TTL 64

void resolve_arp_reply(packet& m, struct ether_header* eth_hdr, struct ether_arp* arp_hdr,
	std::unordered_map<uint32_t, uint8_t*>& arp_table, std::queue<std::pair<packet*, struct route_table_entry*>>& packets);
void resolve_arp_request(packet& m, struct ether_header* eth_hdr, struct ether_arp* arp_hdr);
void resolve_timeout(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr);
void resolve_icmp_echo(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr);
void resolve_destination_unreachable(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr);
void resolve_no_arp_entry(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr,
	std::queue<std::pair<packet*, struct route_table_entry*>>& packets, struct route_table_entry* r_entry);
void resolve_forwarding(packet& m, struct ether_header* eth_hdr, struct iphdr* ip_hdr, struct icmphdr* icmp_hdr,
	std::unordered_map<uint32_t, uint8_t*>& arp_table, struct route_table_entry* r_entry);

#endif
