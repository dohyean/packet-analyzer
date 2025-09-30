#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x02(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x02"});
    fields.push_back({"function_name", "Read Discrete Inputs"});

    if(type == "request"){
        if (pdu_end - pdu_start < 5) {
            throw std::runtime_error("Invalid Modbus 0x02 request: PDU too short");
        }
        uint16_t start_addr = (frame[pdu_start+1] << 8) | frame[pdu_start+2];
        uint16_t quantity_inputs = (frame[pdu_start+3] << 8) | frame[pdu_start+4];

        if(quantity_inputs < 1 || quantity_inputs > 2000) {
            throw std::runtime_error("Invalid Modbus 0x02 request: Quantity of Inputs out of range");
        }

        fields.push_back({"Starting Address", std::to_string(start_addr)});
        fields.push_back({"Quantity of Inputs", std::to_string(quantity_inputs)});
    }
    else if(type == "response"){
        if (pdu_end - pdu_start < 3) {
            throw std::runtime_error("Invalid Modbus 0x02 response: PDU too short");
        }
        uint8_t byte_count = frame[pdu_start+1];
        fields.push_back({"type", "response"});
        fields.push_back({"Byte Count", std::to_string(byte_count)});

        std::stringstream bits;
        for (int i = 0; i < byte_count; i++) {
            uint8_t byte = frame[pdu_start+2+i];
            for (int bit = 0; bit < 8; bit++) {
                bits << ((byte >> bit) & 0x01);
                if (i*8 + bit + 1 < byte_count*8) bits << ",";
            }
        }
        fields.push_back({"input_status", bits.str()});
    }
    return fields;
}