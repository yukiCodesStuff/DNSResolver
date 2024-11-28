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

    // Main Operations
    void doReverseDNSLookup();
    void doDNSLookup();
};