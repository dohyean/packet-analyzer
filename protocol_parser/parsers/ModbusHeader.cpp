#include "ModbusHeader.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <string>

std::vector<std::pair<int,std::string>> ModbusHeader::FUNCTION_NAMES = {
    // Common
    {0x01, "Read Coils"}, 
    {0x02, "Read Discrete Inputs"}, 
    {0x03, "Read Holding Registers"},
    {0x04, "Read Input Registers"}, 
    {0x05, "Write Single Coil"}, 
    {0x06, "Write Single Register"},
    {0x0F, "Write Multiple Coils"}, 
    {0x10, "Write Multiple Registers"}, 
    {0x14, "Read File Record"},
    {0x15, "Write File Record"}, 
    {0x16, "Mask Write Register"}, 
    {0x17, "Read/Write Multiple Registers"},
    {0x18, "Read FIFO Queue"}, 
    {0x2B, "Read Device Identification"},

    // Serial Line Only 
    {0x07, "Read Exception Status"}, 
    {0x08, "Diagnostics"}, 
    {0x0B, "Get Com Event Counter"},
    {0x0C, "Get Comm Event Log"}, 
    {0x11, "Report Server ID"}
};

std::vector<std::pair<int,std::string>> ModbusHeader::EXCEPTION_NAMES = {
    // Exception Codes
    {0x01, "ILLEGAL FUNCTION"}, 
    {0x02, "ILLEGAL DATA ADDRESS"},
    {0x03, "ILLEGAL DATA VALUE"}, 
    {0x04, "SERVER DEVICE FAILURE"},
    {0x05, "ACKNOWLEDGE"}, 
    {0x06, "SERVER DEVICE BUSY"},
    {0x08, "MEMORY PARITY ERROR"}, 
    {0x0A, "GATEWAY PATH UNAVAILABLE"},
    {0x0B, "GATEWAY TARGET DEVICE FAILED TO RESPOND"}
};

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type) {
    // if (frame.size() < (size_t)(pdu_end)) {
    //     throw std::runtime_error("pdu too small");
    // }
    uint8_t func = frame[pdu_start];
    if (func & 0x80) return parseException(frame, pdu_start, pdu_end);

    if (func == 0x01) return parse_0x01(frame, pdu_start, pdu_end, type);
    if (func == 0x02) return parse_0x02(frame, pdu_start, pdu_end, type);
    if (func == 0x03) return parse_0x03(frame, pdu_start, pdu_end, type);

    std::stringstream ss;
    ss << "Unsupported Function Code: 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)func;
    throw std::runtime_error(ss.str());
}


// 아래는 추후 분할 예정
std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x04(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type) {
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x04"});
    fields.push_back({"function_name", "Read Input Registers"});

    if (pdu_end - pdu_start == 5) {
        uint16_t start_addr = (frame[pdu_start+1]<<8) | frame[pdu_start+2];
        uint16_t qty = (frame[pdu_start+3]<<8) | frame[pdu_start+4];
        fields.push_back({"starting_address", std::to_string(start_addr)});
        fields.push_back({"quantity_of_registers", std::to_string(qty)});
    } else {
        uint8_t byte_count = frame[pdu_start+1];
        fields.push_back({"type", "response"});
        fields.push_back({"byte_count", std::to_string(byte_count)});
        std::vector<uint16_t> regs;
        for (int i=0; i<byte_count/2; i++) {
            uint16_t reg = (frame[pdu_start+2+i*2]<<8) | frame[pdu_start+3+i*2];
            regs.push_back(reg);
        }
        std::stringstream ss;
        for (size_t i=0; i<regs.size(); i++) {
            ss << regs[i];
            if (i+1 < regs.size()) ss << ",";
        }
        fields.push_back({"registers", ss.str()});
    }
    return fields;
}

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parseException(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end) {
    std::vector<std::pair<std::string,std::string>> fields;
    uint8_t func = frame[pdu_start];
    uint8_t ex_code = frame[pdu_start+1];

    fields.push_back({"function_code", "0x" + int_to_hex(func)});
    fields.push_back({"type", "error"});
    fields.push_back({"exception_code", std::to_string(ex_code)});

    std::string ex_name = "Unknown";
    for (auto &kv : EXCEPTION_NAMES) {
        if (kv.first == ex_code) { 
            ex_name = kv.second; 
            break; 
        }
    }
    fields.push_back({"exception_message", ex_name});
    return fields;
}

std::string ModbusHeader::int_to_hex(uint8_t val) {
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)val;
    return ss.str();
}
