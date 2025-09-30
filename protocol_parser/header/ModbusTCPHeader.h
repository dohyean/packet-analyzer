#ifndef MODBUSTCPHEADER_H
#define MODBUSTCPHEADER_H

#include <vector>
#include <string>
#include <tuple>
#include <cstdint>

class ModbusTCPHeader {
public:
    static std::tuple<std::vector<std::pair<std::string,std::string>>, int, int>
    modbus_tcp_header_parser(const std::vector<uint8_t>& frame, int modbus_offset);
};

#endif
