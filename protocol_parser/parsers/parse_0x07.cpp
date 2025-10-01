#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x07(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x07"});
    fields.push_back({"function_name", "Read Exception Status"});

    if(type == "request"){
        // request PDU 유효성 검사
        if (frame.size() - (size_t)(pdu_start) < 1) {
            throw std::runtime_error("Invalid Modbus 0x07 request: PDU too short");
        }
        if(frame.size() - (size_t)pdu_start > 1) {
            throw std::runtime_error("Invalid Modbus 0x07 request: PDU too long");
        }
    }
    else if(type == "response"){
        // response PDU 유효성 검사
        if (frame.size() - (size_t)pdu_start < 2) {
            throw std::runtime_error("Invalid Modbus 0x06 response: PDU too short");
        }
        if (frame.size() - (size_t)pdu_start > 2) {
            throw std::runtime_error("Invalid Modbus 0x06 response: PDU too long");
        }

        // response input_data 추출
        uint8_t input_data = frame[pdu_start+1];

        // response 필드 추가
        fields.push_back({"Input Data", std::to_string(input_data)});
    }
    return fields;
}