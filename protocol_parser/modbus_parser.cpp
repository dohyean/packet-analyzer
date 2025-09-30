#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <string>
#include <cstdint>

#include "header/EtherHeader.h"
#include "header/IPv4Header.h"
#include "header/TCPHeader.h"
#include "header/ModbusTCPHeader.h"
#include "header/ModbusHeader.h"

using namespace std;

vector<uint8_t> hex_to_bytes(const string& hex_data) {
    vector<uint8_t> frame;
    if (hex_data.find(' ') != string::npos) {
        stringstream ss(hex_data);
        string byteStr;
        while (ss >> byteStr) {
            uint8_t byte = static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16));
            frame.push_back(byte);
        }
    } else {
        for (size_t i = 0; i < hex_data.size(); i += 2) {
            string byteStr = hex_data.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16));
            frame.push_back(byte);
        }
    }
    return frame;
}

string classify_req_res_error(
    const vector<pair<string,string>>& ip_fields,
    const vector<uint8_t>& frame,
    int pdu_start, int pdu_end,
    const string& scada_ip
) {
    string src_ip, dst_ip;
    for (auto &kv : ip_fields) {
        if (kv.first == "src_ip") src_ip = kv.second;
        if (kv.first == "dst_ip") dst_ip = kv.second;
    }

    uint8_t func = frame[pdu_start];
    bool is_error = (func >= 0x80);

    if (is_error) return "error";

    if (src_ip == scada_ip) {
        return "request";
    } else {
        return "response";
    }
}


void process_frame(const vector<uint8_t>& frame) {
    // cout << "======================================== Ethernet 결과\n";
    auto [dst, src, etype] = EtherHeader::ethernet_header_parser(frame);
    // cout << "  dst_mac    : " << EtherHeader::format_mac(dst.data()) << "\n";
    // cout << "  src_mac    : " << EtherHeader::format_mac(src.data()) << "\n";
    // cout << "  ether_type : 0x" << hex << setw(4) << setfill('0') << etype
    //      << dec << " (" << EtherHeader::format_ether_type(etype) << ")\n";

    // cout << "======================================== IPv4 결과\n";
    auto [ip_fields, tcp_offset] = IPv4Header::ipv4_header_parser(frame);
    // for (auto &kv : ip_fields) cout << "  " << kv.first << " : " << kv.second << "\n";
    // cout << "  tcp_offset        : " << tcp_offset << "\n";

    // cout << "======================================== TCP 결과\n";
    auto [tcp_fields, modbus_offset] = TCPHeader::tcp_header_parser(frame, tcp_offset);
    // for (auto &kv : tcp_fields) cout << "  " << kv.first << " : " << kv.second << "\n";
    // cout << "  mobus/TCP offset : " << modbus_offset << "\n";

    // cout << "======================================== modbus/TCP 결과\n";
    auto [mbtcp_fields, pdu_start, pdu_end] = ModbusTCPHeader::modbus_tcp_header_parser(frame, modbus_offset);
    // for (auto &kv : mbtcp_fields) cout << "  " << kv.first << " : " << kv.second << "\n";
    // cout << "  PDU start      : " << pdu_start << "\n";
    // cout << "  PDU end        : " << pdu_end << "\n";

    cout << "======================================== req, res, err 결과\n";
    string type = classify_req_res_error(ip_fields, frame, pdu_start, pdu_end, "185.175.0.3");
    cout << "[TYPE] " << type << "\n";

    cout << "======================================== modbus PDU 결과\n";
    try {
        auto mb_fields = ModbusHeader::parse(frame, pdu_start, pdu_end, type);
        for (auto &kv : mb_fields) {
            cout << "  " << kv.first << " : " << kv.second << "\n";
        }
    } catch (const std::exception &e) {
        cerr << "  [Modbus PDU Parse Error] " << e.what() << "\n";
    }
}


int main() {
    int number = 0;
    // Modbus/TCP Request, Response, Error frames
    vector<string> req_data = {
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 03 6d 40 00 40 06 c3 e4 b9 af 00 03 b9 af 00 05 e6 54 01 f6 a6 d0 cc 60 41 89 89 a6 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 77 32 eb 86 7f 00 03 00 00 00 06 01 01 00 19 00 01", // 0x01
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 66 7e 40 00 40 06 60 d3 b9 af 00 03 b9 af 00 05 e6 5a 01 f6 9c 95 77 8a 9a ce 61 dd 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 a1 32 eb 86 aa 00 05 00 00 00 06 01 02 00 05 00 01", // 0X02
    
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 06 01 04 00 23 00 02", // 0x04
    };
    vector<uint8_t> req_frame = hex_to_bytes(req_data[number]);
    
    vector<string> res_data = {
        "02 42 b9 af 00 03 02 42 b9 af 00 05 08 00 45 00 00 3e 5b be 40 00 40 06 6b 95 b9 af 00 05 b9 af 00 03 01 f6 e6 54 41 89 89 a6 a6 d0 cc 6c 80 18 01 fd 73 97 00 00 01 01 08 0a 32 eb 86 80 84 5b 99 77 00 03 00 00 00 04 01 01 01 00", // 0x01
        "02 42 b9 af 00 03 02 42 b9 af 00 05 08 00 45 00 00 3e 6d 4f 40 00 40 06 5a 04 b9 af 00 05 b9 af 00 03 01 f6 e6 5a 9a ce 61 dd 9c 95 77 96 80 18 01 fd 73 97 00 00 01 01 08 0a 32 eb 86 ab 84 5b 99 a1 00 05 00 00 00 04 01 02 01 00", // 0X02
    
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 05 b9 af 00 03 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 07 01 04 04 11 11 22 22", // 0x04
    };
    vector<uint8_t> res_frame = hex_to_bytes(res_data[number]);

    vector<string> err_data = {
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 81 01", // exception 0x01
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 82 02", // exception 0x02
    
    
        "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 84 02", // exception 0x04
    };
    vector<uint8_t> err_frame = hex_to_bytes(err_data[number]);

    string SCADA_IP = "185.175.0.3";

    process_frame(req_frame);
    process_frame(res_frame);
    process_frame(err_frame);

    cout << "========================================\n최종 실행 단계: Modbus PDU 파싱\n";
}