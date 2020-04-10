#ifndef PARSER_H_
#define PARSER_H_

#include "skel.h"

#include <unordered_map>
#include <vector>
#include <iostream>
#include <algorithm>
#include <queue>
#include <string.h>
#include <fstream>

#define ADDR_STRING_LEN 16
#define IP_LEN 4
#define MAC_LEN 6

struct route_table_entry {
 public:
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

bool entry_comparator(route_table_entry a, route_table_entry b);
std::vector<struct route_table_entry> parse_route_table();
struct route_table_entry* get_best_route(std::vector<struct route_table_entry>& table, uint32_t ip_dest);
struct arp_table_entry* get_arp_entry(uint32_t ip_dest);
std::string repr(uint32_t addr);
void print_route_entry(struct route_table_entry* r);
void print_route_table(std::vector<struct route_table_entry> table);
uint16_t checksum(void* vdata,size_t length);

#endif
