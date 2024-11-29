# Compiler
CXX = g++

# Flags
CXXFLAGS = -Wall -Wextra -std=c++11

# Targets
TARGET = Driver

# Object files
OBJECTS = Driver.o DNSResolver.o Util.o

# Build the target
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) -v -o $(TARGET) $(OBJECTS)

Driver.o: Driver.cpp
	$(CXX) $(CXXFLAGS) -c Driver.cpp

DNSResolver.o: DNSResolver.cpp DNSResolver.h
	$(CXX) $(CXXFLAGS) -c DNSResolver.cpp -o DNSResolver.o

Util.o: Util.cpp
	$(CXX) $(CXXFLAGS) -c Util.cpp -o Util.o

# Clean up
clean:
	rm -f *.o $(TARGET)

# Test execution
reverseDNSTest: $(TARGET)
	./$(TARGET) 128.194.135.66 8.8.8.8

DNSTest: $(TARGET)
	./$(TARGET) www.amazon.com 8.8.8.8

bigTest: $(TARGET)
	./$(TARGET) www.dhs.gov 128.194.135.79

