#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x04(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x04"});
    fields.push_back({"function_name", "Read Input Registers"});

    if(type == "request"){
        // request PDU 유효성 검사
        if (frame.size() - (size_t)(pdu_start) < 5) {
            throw std::runtime_error("Invalid Modbus 0x04 request: PDU too short");
        }
        if(frame.size() - (size_t)pdu_start > 5) {
            throw std::runtime_error("Invalid Modbus 0x04 request: PDU too long");
        }

        // request starting_address, quantity_of_registers 추출
        uint16_t start_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t quantity_register = (frame[pdu_start+3] << 8) | frame[pdu_start+4];
    
        // request quantity_of_registers 유효성 검사
        if(quantity_register < 1 || quantity_register > 125) {
            throw std::runtime_error("Invalid Modbus 0x04 request: Quantity of Registers out of range");
        }

        // request 필드 추가
        fields.push_back({"Starting Address", std::to_string(start_addr)});
        fields.push_back({"Quantity of Registers", std::to_string(quantity_register)});
    }
    else if(type == "response"){
        // response PDU 유효성 검사
        if (frame.size() - (size_t)pdu_start < 2) {
            throw std::runtime_error("Invalid Modbus 0x04 response: PDU too short");
        }

        // response byte_count 추출
        uint8_t byte_count = frame[pdu_start+1];

        // response byte_count 유효성 검사
        if(byte_count < 2 || byte_count > 250) {
            throw std::runtime_error("Invalid Modbus 0x04 response: Byte count out of range");
        }
        if(byte_count % 2 != 0) {
            throw std::runtime_error("Invalid Modbus 0x04 response: Byte count must be even");
        }
        if(byte_count != frame.size() - pdu_start - 2) {
            throw std::runtime_error("Invalid Modbus 0x03 response: Byte count does not match actual data length");
        }

        // response input register value 추출
        std::vector<uint16_t> registers;
        for (int i = 0; i < byte_count / 2; i++) {
            uint16_t reg_val = (frame[pdu_start + 2 + i * 2] << 8) | frame[pdu_start + 3 + i * 2];
            registers.push_back(reg_val);
        }

        // response input register value 포맷팅
        std::stringstream ss;
        for (size_t i = 0; i < registers.size(); i++) {
            ss << registers[i];
            if (i + 1 < registers.size()) ss << ",";
        }  

        // response 필드 추가
        fields.push_back({"type", "response"});
        fields.push_back({"Byte Count", std::to_string(byte_count)});
        fields.push_back({"Register Values", ss.str()});
    }
    return fields;
}