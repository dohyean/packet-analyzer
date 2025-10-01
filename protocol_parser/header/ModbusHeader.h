#ifndef MODBUSHEADER_H
#define MODBUSHEADER_H

#include <vector>
#include <string>
#include <utility>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <stdexcept>

class ModbusHeader {
public:
    static std::vector<std::pair<int,std::string>> FUNCTION_NAMES;
    static std::vector<std::pair<int,std::string>> EXCEPTION_NAMES;

    static std::vector<std::pair<std::string,std::string>>
    parseException(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end);

    static std::vector<std::pair<std::string,std::string>>
    parse(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x01(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x02(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x03(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x04(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x05(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);


    static std::vector<std::pair<std::string,std::string>>
    parse_0x06(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);


    // 구현 중인 데이터
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x07(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    // 구현을 해야하는 데이터

    static std::vector<std::pair<std::string,std::string>>
    parse_0x08(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x0B(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x0C(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x0F(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);

    static std::vector<std::pair<std::string,std::string>>
    parse_0x10(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x11(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x14(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x15(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x16(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x17(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x18(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
    static std::vector<std::pair<std::string,std::string>>
    parse_0x2B(const std::vector<uint8_t>& frame, int pdu_start, int pdu_end, const std::string type);
    
private:
    static std::string int_to_hex(uint8_t val);
};

#endif
