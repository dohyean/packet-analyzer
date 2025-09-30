#include "IPv4Header.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string IPv4Header::format_ip(const uint8_t* ip) {
    std::stringstream ss;
    for (int i = 0; i < 4; i++) {
        if (i > 0) ss << ".";
        ss << (int)ip[i];
    }
    return ss.str();
}

std::string IPv4Header::format_protocol(uint8_t proto) {
    if (proto == 1) return "ICMP";
    if (proto == 6) return "TCP";
    if (proto == 17) return "UDP";
    return "Unknown";
}

// ipv4_header_parser 구현 (지금 코드 그대로 이동)
std::pair<std::vector<std::pair<std::string,std::string>>, int>
IPv4Header::ipv4_header_parser(const std::vector<uint8_t>& frame, int ip_offset) {
    if (frame.size() < (size_t)(ip_offset + 20)) throw std::runtime_error("IPv4 header too small");

    uint8_t v_ihl = frame[ip_offset];
    int version = (v_ihl >> 4) & 0x0F;
    int ihl_word = v_ihl & 0x0F;
    int ihl_bytes = ihl_word * 4;
    if (version != 4) throw std::runtime_error("IPv4가 아님");
    if (ihl_bytes < 20) throw std::runtime_error("IPv4 header < 20 bytes");

    uint8_t dscp_ecn = frame[ip_offset + 1];
    int dscp = dscp_ecn >> 2;
    int ecn = dscp_ecn & 0b11;

    uint16_t total_length = (frame[ip_offset+2] << 8) | frame[ip_offset+3];
    uint16_t ident = (frame[ip_offset+4] << 8) | frame[ip_offset+5];
    uint16_t flags_frag = (frame[ip_offset+6] << 8) | frame[ip_offset+7];
    int flags = (flags_frag >> 13) & 0x07;
    int frag_offset = flags_frag & 0x1FFF;
    bool flag_df = (flags & 0b010) != 0;
    bool flag_mf = (flags & 0b001) != 0;
    uint8_t ttl = frame[ip_offset+8];
    uint8_t protocol = frame[ip_offset+9];
    uint16_t checksum = (frame[ip_offset+10] << 8) | frame[ip_offset+11];

    const uint8_t* src_ip = &frame[ip_offset + 12];
    const uint8_t* dst_ip = &frame[ip_offset + 16];

    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"version", std::to_string(version)});
    fields.push_back({"ihl_bytes", std::to_string(ihl_bytes)});
    fields.push_back({"dscp", std::to_string(dscp)});
    fields.push_back({"ecn", std::to_string(ecn)});
    fields.push_back({"total_length", std::to_string(total_length)});
    fields.push_back({"identification", std::to_string(ident)});
    fields.push_back({"flags_df", flag_df ? "True" : "False"});
    fields.push_back({"flags_mf", flag_mf ? "True" : "False"});
    fields.push_back({"frag_offset_bytes", std::to_string(frag_offset * 8)});
    fields.push_back({"ttl", std::to_string(ttl)});
    fields.push_back({"protocol", std::to_string(protocol) + " (" + format_protocol(protocol) + ")"});
    fields.push_back({"checksum", [&]{ 
        std::ostringstream ss; 
        ss << "0x" << std::hex << std::nouppercase << checksum; 
        return ss.str(); 
    }()});
    fields.push_back({"src_ip", format_ip(src_ip)});
    fields.push_back({"dst_ip", format_ip(dst_ip)});

    return {fields, ip_offset + ihl_bytes};
}
