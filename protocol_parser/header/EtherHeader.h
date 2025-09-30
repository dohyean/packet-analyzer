#ifndef ETHERHEADER_H
#define ETHERHEADER_H

#include <vector>
#include <string>
#include <tuple>
#include <cstdint>

class EtherHeader {
public:
    static std::string format_mac(const uint8_t* mac);
    static std::string format_ether_type(uint16_t etype);

    static std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, uint16_t>
    ethernet_header_parser(const std::vector<uint8_t>& frame);
};

#endif
