#include "EtherHeader.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string EtherHeader::format_mac(const uint8_t* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    return ss.str();
}

std::string EtherHeader::format_ether_type(uint16_t etype) {
    if (etype == 0x0800) return "IPv4";
    if (etype == 0x0806) return "ARP";
    if (etype == 0x86DD) return "IPv6";
    return "Unknown";
}

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, uint16_t>
EtherHeader::ethernet_header_parser(const std::vector<uint8_t>& frame) {
    if (frame.size() < 14) throw std::runtime_error("14 byte보다 작음");
    std::vector<uint8_t> dst(frame.begin(), frame.begin() + 6);
    std::vector<uint8_t> src(frame.begin() + 6, frame.begin() + 12);
    uint16_t etype = (frame[12] << 8) | frame[13];
    return {dst, src, etype};
}
