#include "DNSResolver.h"

int main(int argc, char* argv[]) {
    
    // Input Handling
    if (argc != 3) {
        printf("[Driver::ERROR] Usage: Driver.cpp <lookup string (hostname or IP)> <DNS server IP>\n");
        return -1;
    }

    char* lookupStr = argv[1];
    char* dnsIP = argv[2];

    DNSResolver dnsResolver(lookupStr, dnsIP);
    dnsResolver.doDNS();
    
    return 0;
}