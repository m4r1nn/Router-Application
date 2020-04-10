#include "./include/parser.h"

// comparator for sorting route table
bool entry_comparator(const struct route_table_entry entry1, const struct route_table_entry entry2) {

    if (entry1.prefix < entry2.prefix) {
        return true;
    }
    if (entry1.prefix == entry2.prefix && __builtin_popcount(entry1.mask) < __builtin_popcount(entry2.mask)) {
        return true;
    }
    return false;
}

// read and parse route table
std::vector<struct route_table_entry> parse_route_table() {

    std::vector<struct route_table_entry> table;
    std::ifstream f("rtable.txt");
    char address[ADDR_STRING_LEN];
    uint32_t interface;

    // read all entries
    while (f >> address) {
        struct route_table_entry entry;
        entry.prefix = inet_addr(address);
        f >> address;
        entry.next_hop = inet_addr(address);
        f >> address;
        entry.mask = inet_addr(address);
        f >> interface;
        entry.interface = interface;

        // add entry to route table
        table.push_back(entry);
    }
    f.close();

    std::sort(table.begin(), table.end(), entry_comparator);
 
    return table;
}

// binary search for finding best entry for next-hop
struct route_table_entry* get_best_route(std::vector<struct route_table_entry>& table, uint32_t ip_dest) {

    int left = 0;
    int right = table.size() - 1;
    while (left <= right) {
        int middle = left + (right - left) / 2;

        // if the entry fits, get that one with maximum mask
        if ((ip_dest & table[middle].mask) == table[middle].prefix) {
            int j = middle;
            while (table[j + 1].prefix == table[middle].prefix) {
                j++;
            }
            return &table[j];
        }

        if ((ip_dest & table[middle].mask) > table[middle].prefix) {
            left = middle + 1;
        } else {
            right = middle - 1;
        }
    }

    return NULL;
}

// string representation for ip address --- for debugging
std::string repr(uint32_t addr) {

    std::string res = "";
    int s = ((addr << 24) >> 24);
    res = res + std::to_string(s) + ".";
    s = ((addr << 16) >> 24);
    res = res + std::to_string(s) + ".";
    s = ((addr << 8) >> 24);
    res = res + std::to_string(s) + ".";
    s = (addr >> 24);
    res = res + std::to_string(s);
    return res; 
}

// print one entry from route table --- for debugging
void print_route_entry(struct route_table_entry* r) {

    std::cout << repr(r->prefix) << " " << repr(r->next_hop) << " " << repr(r->mask) << " " << repr(r->interface) << std::endl;
}

// print route table --- for debugging
void print_route_table(std::vector<struct route_table_entry> table) {

    for (size_t i = 0; i < table.size(); i++) {
        print_route_entry(&table[i]);
    }
}

// function to check and recalculate the checksum for ip and icmp headers
uint16_t checksum(void* vdata, size_t length) {

	// cast the data pointer to one that can be indexed
	char* data = (char*) vdata;

	// initialise the accumulator.
	uint64_t acc = 0xffff;

	// handle any partial block at the start of the data
	unsigned int offset = ((uintptr_t) data) & 3;
	if (offset) {
		size_t count = 4 - offset;
		if (count > length) {
            count=length;
        }
		uint32_t word = 0;
		memcpy(offset + (char*) &word, data, count);
		acc += ntohl(word);
		data += count;
		length -= count;
	}

	// handle any complete 32-bit blocks
	char* data_end = data + (length & ~3);
	while (data != data_end) {
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}
	length &= 3;

	// handle any partial block at the end of the data
	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}

	// handle deferred carries
	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}

	// if the data began at an odd byte address
	// then reverse the byte order to compensate
	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	// return the checksum in network byte order
	return htons(~acc);
}
