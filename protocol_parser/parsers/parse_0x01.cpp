#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x01(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x01"});
    fields.push_back({"function_name", "Read Coils"});

    if(type == "request"){
        if(pdu_end - pdu_start < 5){
            throw std::runtime_error("Invalid Modbus 0x01 request: PDU length too short");
        }

        uint16_t start_addr = (frame[pdu_start + 1] << 8) | frame[pdu_start + 2];
        uint16_t quantity_coils  = (frame[pdu_start + 3] << 8) | frame[pdu_start + 4];

        if (quantity_coils < 1 || quantity_coils > 2000) {
            throw std::runtime_error("Invalid Modbus 0x01 request: Quantity of Coils out of range");
        }

        fields.push_back({"Starting Address", std::to_string(start_addr)});
        fields.push_back({"Quantity of Coils", std::to_string(quantity_coils)});
    }
    else if(type == "response"){
         if (pdu_end - pdu_start < 3) {
            throw std::runtime_error("Invalid Modbus 0x01 response: PDU length too short");
        }
        
        uint8_t byte_count = frame[pdu_start + 1];
        fields.push_back({"Byte Count", std::to_string(byte_count)});
        
        std::stringstream coil_bits;
        for (int i = 0; i < byte_count; i++) {
            uint8_t byte = frame[pdu_start + 2 + i];
            for (int bit = 0; bit < 8; bit++) {
                coil_bits << ((byte >> bit) & 0x01);
                if (i * 8 + bit + 1 < byte_count * 8) coil_bits << ",";
            }
        }
        fields.push_back({"Coil Status", coil_bits.str()});
    }
    return fields;
}