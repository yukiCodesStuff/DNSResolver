#include <iostream>
#include <Util.cpp>
#include <set>
#include <arpa/inet.h>

class DNSResolver {
private:

    // Upon class init
    char* lookupStr = NULL;
    char* dnsIP = NULL;
    bool isReverseLookup = false;

    // Further operations
    char* host = NULL;
    char* IP = NULL;

public:
    DNSResolver(char* lookupStr, char* dnsIP);
    ~DNSResolver();
    void doDNS();
};