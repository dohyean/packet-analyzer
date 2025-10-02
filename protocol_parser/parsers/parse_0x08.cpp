#include "ModbusHeader.h"

// 해당 함수는 추후에 작성 (현재는 불필요)

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x08(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x08"});
    fields.push_back({"function_name", "Diagnostics"});

    if(type == "request"){
        if (frame.size() - (size_t)pdu_start < 3) {
            throw std::runtime_error("Invalid Modbus 0x08 request: PDU too short");
        }
        
        uint16_t sub_func = (frame[pdu_start + 1] << 8) | frame[pdu_start + 2];

        std::string subfunc_name = "RESERVED (not defined)";
        for (auto &kv : SUB_FUNCTION_NAMES) {
            if (kv.first == sub_func) {
                subfunc_name = kv.second;
                break;
            }
        }
        int total_len = frame.size() - pdu_start;
        int data_len = total_len - 3;
        if (data_len > 250) {
            throw std::runtime_error("Invalid Modbus 0x08 request: Data length exceeds maximum allowed");
        }
        if (data_len % 2 != 0) {
            throw std::runtime_error("Invalid Modbus 0x08 request: Data length must be even");
        }

        std::stringstream data_ss;
        for (int i = 0; i < data_len; i += 2) {
            uint16_t word = (frame[pdu_start + 3 + i] << 8) | frame[pdu_start + 3 + i + 1];
            data_ss << "0x" << int_to_hex((word >> 8) & 0xFF) << int_to_hex(word & 0xFF);
            if (i + 2 < data_len) data_ss << ",";
        }

        fields.push_back({"Sub Function Code", "0x" + int_to_hex(sub_func)});
        fields.push_back({"Sub Function Name", subfunc_name});
        fields.push_back({"Data Length", std::to_string(data_len)});
        fields.push_back({"Data", data_ss.str()});        
    }
    else if(type == "response"){
        if (frame.size() - (size_t)pdu_start < 3) {
            throw std::runtime_error("Invalid Modbus 0x08 response: PDU too short");
        }
        
        uint16_t sub_func = (frame[pdu_start + 1] << 8) | frame[pdu_start + 2];

        std::string subfunc_name = "RESERVED (not defined)";
        for (auto &kv : SUB_FUNCTION_NAMES) {
            if (kv.first == sub_func) {
                subfunc_name = kv.second;
                break;
            }
        }
        int total_len = frame.size() - pdu_start;
        int data_len = total_len - 3;
        if (data_len > 250) {
            throw std::runtime_error("Invalid Modbus 0x08 response: Data length exceeds maximum allowed");
        }
        if (data_len % 2 != 0) {
            throw std::runtime_error("Invalid Modbus 0x08 response: Data length must be even");
        }

        std::stringstream data_ss;
        for (int i = 0; i < data_len; i += 2) {
            uint16_t word = (frame[pdu_start + 3 + i] << 8) | frame[pdu_start + 3 + i + 1];
            data_ss << "0x" << int_to_hex((word >> 8) & 0xFF) << int_to_hex(word & 0xFF);
            if (i + 2 < data_len) data_ss << ",";
        }

        fields.push_back({"Sub Function Code", "0x" + int_to_hex(sub_func)});
        fields.push_back({"Sub Function Name", subfunc_name});
        fields.push_back({"Data Length", std::to_string(data_len)});
        fields.push_back({"Data", data_ss.str()});
    }
    return fields;
}