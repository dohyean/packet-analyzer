#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x02(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x02"});
    fields.push_back({"function_name", "Read Discrete Inputs"});

    if(type == "request"){
        // request PDU 유효성 검사
        if (frame.size() - (size_t)pdu_start < 5) {
            throw std::runtime_error("Invalid Modbus 0x02 request: PDU too short");
        }

        // request starting_address, quantity_of_inputs 추출
        uint16_t start_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t quantity_inputs = (frame[pdu_start+3] << 8) | frame[pdu_start+4];

        // request quantity_of_inputs 유효성 검사
        if(quantity_inputs < 1 || quantity_inputs > 2000) {
            throw std::runtime_error("Invalid Modbus 0x02 request: Quantity of Inputs out of range");
        }

        // request 필드 추가
        fields.push_back({"Starting Address", std::to_string(start_addr)});
        fields.push_back({"Quantity of Inputs", std::to_string(quantity_inputs)});
    }
    else if(type == "response"){
        // response PDU 유효성 검사
        if (frame.size() - (size_t)pdu_start < 3) {
            throw std::runtime_error("Invalid Modbus 0x02 response: PDU too short");
        }

        // response byte_count 추출
        uint8_t byte_count = frame[pdu_start+1];

        // response byte_count 유효성 검사
        if (byte_count < 1 || byte_count > 250) {
            throw std::runtime_error("Invalid Modbus 0x02 response: Byte count out of range");
        }
        if (byte_count != frame.size() - pdu_start - 2) {
            throw std::runtime_error("Invalid Modbus 0x02 response: Byte count does not match actual data length");
        }

        // response input status 추출
        std::stringstream bits;
        for (int i = 0; i < byte_count; i++) {
            uint8_t byte = frame[pdu_start+2+i];
            for (int bit = 0; bit < 8; bit++) {
                bits << ((byte >> bit) & 0x01);
                if (i*8 + bit + 1 < byte_count*8) bits << ",";
            }
        }

        // response 필드 추가
        fields.push_back({"Byte Count", std::to_string(byte_count)});
        fields.push_back({"Input Status", bits.str()});
    }
    return fields;
}