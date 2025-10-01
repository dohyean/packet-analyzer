#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x06(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x06"});
    fields.push_back({"function_name", "Write Single Register"});

    if(type == "request"){
        // request PDU 유효성 검사
        if (frame.size() - (size_t)(pdu_start) < 5) {
            throw std::runtime_error("Invalid Modbus 0x06 request: PDU too short");
        }
        if(frame.size() - (size_t)pdu_start > 5) {
            throw std::runtime_error("Invalid Modbus 0x06 request: PDU too long");
        }

        // request register_address, register_value 추출
        uint16_t register_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t register_value = (frame[pdu_start+3] << 8) | frame[pdu_start+4];
    
        // request 필드 추가
        fields.push_back({"Register Address", std::to_string(register_addr)});
        fields.push_back({"Register Value", std::to_string(register_value)});
    }
    else if(type == "response"){
        // response PDU 유효성 검사
        if (frame.size() - (size_t)pdu_start < 5) {
            throw std::runtime_error("Invalid Modbus 0x06 response: PDU too short");
        }
        if (frame.size() - (size_t)pdu_start > 5) {
            throw std::runtime_error("Invalid Modbus 0x06 response: PDU too long");
        }

        // response register_address, register_value 추출
        uint16_t register_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t register_value = (frame[pdu_start+3] << 8) | frame[pdu_start+4];

        // response 필드 추가
        fields.push_back({"Register Address", std::to_string(register_addr)});
        fields.push_back({"Register Value", std::to_string(register_value)});
    }
    return fields;
}