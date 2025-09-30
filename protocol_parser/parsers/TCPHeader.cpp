#include "TCPHeader.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::pair<std::vector<std::pair<std::string,std::string>>, int>
TCPHeader::tcp_header_parser(const std::vector<uint8_t>& frame, int tcp_offset) {
    if (frame.size() < (size_t)(tcp_offset + 20)) throw std::runtime_error("TCP header too small");

    uint16_t src_port = (frame[tcp_offset] << 8) | frame[tcp_offset+1];
    uint16_t dst_port = (frame[tcp_offset+2] << 8) | frame[tcp_offset+3];
    uint32_t seq_num = (frame[tcp_offset+4] << 24) | (frame[tcp_offset+5] << 16) | (frame[tcp_offset+6] << 8) | frame[tcp_offset+7];
    uint32_t ack_num = (frame[tcp_offset+8] << 24) | (frame[tcp_offset+9] << 16) | (frame[tcp_offset+10] << 8) | frame[tcp_offset+11];
    uint16_t HL_flags = (frame[tcp_offset+12] << 8) | frame[tcp_offset+13];
    uint16_t window = (frame[tcp_offset+14] << 8) | frame[tcp_offset+15];
    uint16_t checksum = (frame[tcp_offset+16] << 8) | frame[tcp_offset+17];
    uint16_t urg_ptr = (frame[tcp_offset+18] << 8) | frame[tcp_offset+19];

    int data_offset_words = (HL_flags >> 12) & 0xF;
    int HL = data_offset_words * 4;

    uint8_t std_flags = HL_flags & 0xFF;
    std::string flags_str;
    if (std_flags & 0x10) flags_str += "ACK|";
    if (std_flags & 0x08) flags_str += "PSH|";
    if (!flags_str.empty()) flags_str.pop_back();

    std::stringstream options;
    if (HL > 20) {
        for (int i = 0; i < HL-20; i++) {
            if (i > 0) options << " ";
            options << std::hex << std::setw(2) << std::setfill('0') << (int)frame[tcp_offset+20+i];
        }
    }

    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"src_port", std::to_string(src_port)});
    fields.push_back({"dst_port", std::to_string(dst_port)});
    std::stringstream ss1; ss1 << "0x" << std::hex << seq_num; fields.push_back({"sequence_number", ss1.str()});
    std::stringstream ss2; ss2 << "0x" << std::hex << ack_num; fields.push_back({"ack_number", ss2.str()});
    fields.push_back({"header_length", std::to_string(HL)});
    fields.push_back({"flags", flags_str});
    std::stringstream ss3; ss3 << "0x" << std::hex << window; fields.push_back({"window_size", ss3.str()});
    std::stringstream ss4; ss4 << "0x" << std::hex << checksum; fields.push_back({"checksum", ss4.str()});
    fields.push_back({"urgent_pointer", std::to_string(urg_ptr)});
    fields.push_back({"options_hex", options.str()});

    return {fields, tcp_offset + HL};
}
