#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x05(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x05"});
    fields.push_back({"function_name", "Write Single Coil"});

    if(type == "request"){
        // request PDU 유효성 검사
        if (frame.size() - (size_t)(pdu_start) < 5) {
            throw std::runtime_error("Invalid Modbus 0x05 request: PDU too short");
        }
        if(frame.size() - (size_t)pdu_start > 5) {
            throw std::runtime_error("Invalid Modbus 0x05 request: PDU too long");
        }

        // request ouput_address, ouput_value 추출
        uint16_t output_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t output_value = (frame[pdu_start+3] << 8) | frame[pdu_start+4];
    
        // request ouput_value 유효성 검사
        if(output_value != 0x0000 && output_value != 0xFF00) {
            throw std::runtime_error("Invalid Modbus 0x05 request: Output Value must be 0x0000 or 0xFF00");
        }

        // request 필드 추가
        fields.push_back({"Output Address", std::to_string(output_addr)});
        fields.push_back({"Output Value", std::to_string(output_value)});
    }
    else if(type == "response"){
        // response PDU 유효성 검사
        if (frame.size() - (size_t)pdu_start < 5) {
            throw std::runtime_error("Invalid Modbus 0x05 response: PDU too short");
        }
        if (frame.size() - (size_t)pdu_start > 5) {
            throw std::runtime_error("Invalid Modbus 0x05 response: PDU too long");
        }

        // response ouput_address, ouput_value 추출
        uint16_t output_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t output_value = (frame[pdu_start+3] << 8) | frame[pdu_start+4];

        // response ouput_value 유효성 검사
        if(output_value != 0x0000 && output_value != 0xFF00) {
            throw std::runtime_error("Invalid Modbus 0x05 request: Output Value must be 0x0000 or 0xFF00");
        }

        // response 필드 추가
        fields.push_back({"Output Address", std::to_string(output_addr)});
        fields.push_back({"Output Value", std::to_string(output_value)});
    }
    return fields;
}