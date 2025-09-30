#ifndef TCPHEADER_H
#define TCPHEADER_H

#include <vector>
#include <string>
#include <utility>
#include <cstdint>

class TCPHeader {
public:
    static std::pair<std::vector<std::pair<std::string,std::string>>, int>
    tcp_header_parser(const std::vector<uint8_t>& frame, int tcp_offset);
};

#endif
