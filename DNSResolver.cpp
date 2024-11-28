#include "DNSResolver.h"

DNSResolver::DNSResolver(char* lookupStr, char* dnsIP) : lookupStr(lookupStr), dnsIP(dnsIP) {
    // Populate fields based on operation type
    this->isReverseLookup = inet_addr(lookupStr) == INADDR_NONE ? false : true;
    if (this->isReverseLookup) this->IP = lookupStr;
    else this->host = lookupStr;   
}

DNSResolver::~DNSResolver() {

}

