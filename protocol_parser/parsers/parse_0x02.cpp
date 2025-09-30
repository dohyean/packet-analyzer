#include "ModbusHeader.h"

std::vector<std::pair<std::string,std::string>>
ModbusHeader::parse_0x02(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type){
    std::vector<std::pair<std::string,std::string>> fields;
    fields.push_back({"function_code", "0x01"});
    fields.push_back({"function_name", "Read Coils"});

    if(type == "request"){
    }
    else if(type == "response"){
    }
    return fields;
}