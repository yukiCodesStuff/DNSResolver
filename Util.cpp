#include <string>

#define MAX_DNS_LEN 512
#define MAX_ATTEMPTS 3

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */ 

/* query classes */
#define DNS_INET 1

/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */

#define DNS_OK 0 /* success */
#define DNS_FORMAT 1 /* format error (unable to interpret) */
#define DNS_SERVERFAIL 2 /* can�t find authority nameserver */
#define DNS_ERROR 3 /* no DNS entry */
#define DNS_NOTIMPL 4 /* not implemented */
#define DNS_REFUSED 5 /* server refused the query */

typedef unsigned short u_short; // 2 bytes

// 12 bytes long; 3 fields are 0
#pragma pack(push, 1)
struct QueryHeader {
    u_short _type;
    u_short _class;

    QueryHeader(u_short _type, u_short _class) : _type(_type), _class(_class) {}
};

struct FixedDNSHeader {
    u_short _ID;
    u_short _flags;
    u_short _questions;
    u_short _answers;
    u_short _authority;
    u_short _additional;
};

struct DNSQuestion {
    std::string qname;
    QueryHeader qheader;
};

struct DNSRecord {
    std::string name;
    u_short _type;
    u_short _class;
    int _ttl;
    u_short _len;
    std::string _data;
};

struct DNSRecordHeader {
    u_short _type;
    u_short _class;
    int _ttl;
    u_short _len;
};
#pragma pack(pop)

// Function to print the contents of the packet
void printPacket(const unsigned char* packet, size_t packetSize) {
	for (size_t i = 0; i < packetSize; i++) {
		// Print in hexadecimal
		printf("%02x ", packet[i]);
	}
	printf("\n");
}