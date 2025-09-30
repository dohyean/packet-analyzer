#ifndef IPV4HEADER_H
#define IPV4HEADER_H

#include <vector>
#include <string>
#include <utility>
#include <cstdint>

class IPv4Header {
public:
    static std::string format_ip(const uint8_t* ip);
    static std::string format_protocol(uint8_t proto);

    static std::pair<std::vector<std::pair<std::string,std::string>>, int>
    ipv4_header_parser(const std::vector<uint8_t>& frame, int ip_offset = 14);
};

#endif
