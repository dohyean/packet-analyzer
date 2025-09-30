#include "ModbusTCPHeader.h"
#include <stdexcept>

std::tuple<std::vector<std::pair<std::string,std::string>>, int, int>
ModbusTCPHeader::modbus_tcp_header_parser(const std::vector<uint8_t>& frame, int modbus_offset) {
    if (frame.size() < (size_t)(modbus_offset + 7)) throw std::runtime_error("modbus header too small");
    uint16_t tid = (frame[modbus_offset]<<8) | frame[modbus_offset+1];
    uint16_t pid = (frame[modbus_offset+2]<<8) | frame[modbus_offset+3];
    uint16_t length = (frame[modbus_offset+4]<<8) | frame[modbus_offset+5];
    uint8_t uid = frame[modbus_offset+6];

    int pdu_length = length - 1;
    int pdu_start = modbus_offset + 7;
    int pdu_end = pdu_start + pdu_length;

    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"transaction_id", std::to_string(tid)});
    fields.push_back({"protocol_id", std::to_string(pid)});
    fields.push_back({"length", std::to_string(length)});
    fields.push_back({"unit_id", std::to_string(uid)});
    fields.push_back({"pdu_length", std::to_string(pdu_length)});

    return {fields, pdu_start, pdu_end};
}
