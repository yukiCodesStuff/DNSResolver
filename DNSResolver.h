#include <iostream>
#include <set>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#include "Util.cpp"

class DNSResolver {
private:

    // Upon class init
    char* dnsIP = NULL;
    bool isReverseLookup = false;

    // Further operations
    char* host = NULL;
    char* IP = NULL;

    // Connction variables
    int sock;
    struct sockaddr_in local;
    struct sockaddr_in remote;

public:

    // Constructor and Destructor
    DNSResolver(char* lookupStr, char* dnsIP);
    ~DNSResolver();

    // Helper Functions
    void doDNS();
    int doConnect();
    int CheckHeader(FixedDNSHeader* dnsResponseHeader, u_short id, u_short rcode);
    int ParseQuestions(unsigned char* responseBuf, int pos); // Return question size
    int ParseRecords(unsigned char* responseBuf, int pos);

    // Main Operations
    void ParseData(char* responseBuf);
    void doReverseDNSLookup();
    void doDNSLookup();
};