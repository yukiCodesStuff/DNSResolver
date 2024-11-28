#include "DNSResolver.h"

DNSResolver::DNSResolver(char* lookupStr, char* dnsIP) : lookupStr(lookupStr), dnsIP(dnsIP) {
    // Populate fields based on operation type
    this->isReverseLookup = inet_addr(lookupStr) == INADDR_NONE ? false : true;
    if (this->isReverseLookup) this->IP = lookupStr;
    else this->host = lookupStr;   
}

DNSResolver::~DNSResolver() {

}

int DNSResolver::doConnect() {

    // AF_INET: IPv4
	// SOCK_DGRAM: UDP (datagram-based protocol)
	// Protocl is specified as 0
	if ((this->sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("[DNSResolver::doConnect::ERROR] Failed to create socket\n");
		return DNS_ERROR;
	}

    // Set timeout using struct timeval
    struct timeval timeout;
    timeout.tv_sec = 1; // seconds
    timeout.tv_usec = 0; // 1000 milliseconds (1 second)

    if (setsockopt(this->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        // Print error details using strerror
        printf("[DNSResolver::doConnect::ERROR] setsockopt() failed: %s\n", strerror(errno));
        close(this->sock);
        return DNS_ERROR;
    }

    /*
		Note that local.sin_addr specifies which local IP address you are binding the socket to, which
		may be important if you have multiple network cards in the computer. Since you do not have a
		preference in this homework, INADDR_ANY allows you to receive packets on all physical
		interfaces of the system.
	*/
	memset(&this->local, 0, sizeof(this->local)); // initialize local member variables with 0
	this->local.sin_family = AF_INET;
	this->local.sin_addr.s_addr = INADDR_ANY;
	this->local.sin_port = htons(0); // find next available (clarify with prof)
	if (bind(this->sock, (struct sockaddr*)&this->local, sizeof(this->local)) == -1) {
		printf("[DNSResolver::doConnect::ERROR] Bind failure\n");
		close(this->sock);
		return DNS_ERROR;
	}

	// There is no connect phase; sockets can be used immediately after binding
	memset(&this->remote, 0, sizeof(this->remote));
	this->remote.sin_family = AF_INET;
	this->remote.sin_addr.s_addr = inet_addr(this->dnsIP);
	this->remote.sin_port = htons(53); // DNS port on server

    return DNS_OK;
}

void DNSResolver::doDNS() {
    if (this->isReverseLookup) this->doReverseDNSLookup();
    else this->doDNSLookup();
}

void DNSResolver::doReverseDNSLookup() {

    // Construct query
	char packet[MAX_DNS_LEN];
	memset(packet, 0, MAX_DNS_LEN);
	int pkt_size = strlen(this->IP) + 2 + sizeof(QueryHeader) + sizeof(FixedDNSHeader);

	// Setting DNS header values
	struct FixedDNSHeader dnsHeader {
		htons(rand() % 65536), // tx id
			htons(DNS_QUERY | DNS_RD | DNS_STDQUERY), // set DNS query flags
			htons(1), // number of questions
			htons(0), // number of resource records
			htons(0), // number of name server resource records in the authority records section
			htons(0) // number of resource records in the additional records section
	};
	memcpy(packet, &dnsHeader, sizeof(dnsHeader));

    // Set qname
	char qname[MAX_DNS_LEN];
	char* qptr = qname;

	// Reverse byte order then convert to string
	struct in_addr addr;
	inet_pton(AF_INET, this->IP, &addr);
	addr.s_addr = ntohl(addr.s_addr);
	const char* reversedIP = inet_ntoa(addr);

	// Copy into qname
	snprintf(qname, sizeof(qname), "%s.in-addr.arpa", reversedIP);

	// Make a copy to perform operations on, need original for printing out
	char qnameCopy[MAX_DNS_LEN];
	strncpy(qnameCopy, qname, sizeof(qnameCopy));
	qnameCopy[sizeof(qnameCopy) - 1] = '\0';

	// Add QNAME into packet
	char* token = strtok(qnameCopy, ".");
	char* p = packet + sizeof(dnsHeader);
	while (token) {
		size_t len = strlen(token);
		*p++ = len;
		memcpy(p, token, len);
		p += len;
		token = strtok(NULL, ".");
	}
	*p++ = 0;

	// Set query header values
	*((uint16_t*)p) = htons(DNS_PTR); 
	p += sizeof(uint16_t);
	*((uint16_t*)p) = htons(DNS_INET);
	p += sizeof(uint16_t);

    printf("Query   : %s, type %hu, TXID 0x%04X\n", qname, DNS_PTR, dnsHeader._ID);
	printf("Server  : %s\n", this->dnsIP);
	printf("********************************\n");

    if (doConnect() != DNS_OK) {
        printf("[DNSResovler::doReverseDNSLookup::ERROR] Connection Failure\n");
        return;
    }

    int querySize = sizeof(FixedDNSHeader) + strlen(qname) + sizeof(QueryHeader) + 2;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        printf("Attempt %d with %d bytes... ", attempt, querySize);

        // Timer
        clock_t timer = clock();

        // Send query
        if (sendto(this->sock, packet, querySize, 0, (struct sockaddr*)&remote, sizeof(remote)) == -1) {
			printf("[DNSResolver::doReverseDNSLookup::ERROR] sendto() failure\n");
			close(this->sock);
			return;
		}

        // Receive the response
		char responseBuf[MAX_DNS_LEN];
		int responseLen = recvfrom(sock, responseBuf, MAX_DNS_LEN, 0, NULL, NULL);
		if (responseLen == -1) {
			printf("[DNSResolver::doReverseDNSLookup::ERROR] recvfrom() failure\n");
			close(sock);
			return;
		}

        // Print status
        float elapsedTime = (clock() - timer) / CLOCKS_PER_SEC;
        printf(" response in %.0f ms with %d bytes\n", elapsedTime, responseLen);

        // Helper
        Util::printPacket((unsigned char*)&responseBuf, responseLen);
    }
}

void DNSResolver::doDNSLookup() {
    return;
}
