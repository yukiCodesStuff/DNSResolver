#include <iostream>
#include <Util.cpp>
#include <set>

class DNSHelper {
private:
    char* host = NULL;
    char* IP = NULL;
public:
    DNSHelper(char* hostOrIP, char* DNSServerIP);
    ~DNSHelper();
    void doDNS();
};