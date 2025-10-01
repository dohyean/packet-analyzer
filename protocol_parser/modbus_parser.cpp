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
#include "test_case.h"

#include <iostream>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

std::vector<uint8_t> hex_to_bytes(std::string hex_data) {
    hex_data.erase(std::remove_if(hex_data.begin(), hex_data.end(),
                                  [](unsigned char c){ return std::isspace(c); }),
                   hex_data.end());

    if (hex_data.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex string length: must be even, but got " + std::to_string(hex_data.size()));
    }

    std::vector<uint8_t> frame;
    frame.reserve(hex_data.size() / 2);
    for (size_t i = 0; i < hex_data.size(); i += 2) {
        std::string byte_str = hex_data.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        frame.push_back(byte);
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
        throw;
    }
}


json process_frame_json(const vector<uint8_t>& frame) {
    json result;

    // Ethernet
    auto [dst, src, etype] = EtherHeader::ethernet_header_parser(frame);
    result["Ethernet"]["dst_mac"] = EtherHeader::format_mac(dst.data());
    result["Ethernet"]["src_mac"] = EtherHeader::format_mac(src.data());
    std::ostringstream oss;
    oss << std::hex << std::setw(4) << std::setfill('0') << etype;
    result["Ethernet"]["ether_type"] = "0x" + oss.str();
    
    // IPv4
    auto [ip_fields, tcp_offset] = IPv4Header::ipv4_header_parser(frame);
    for (auto &kv : ip_fields) {
        result["IPv4"][kv.first] = kv.second;
    }
    result["IPv4"]["tcp_offset"] = tcp_offset;

    // TCP
    auto [tcp_fields, modbus_offset] = TCPHeader::tcp_header_parser(frame, tcp_offset);
    for (auto &kv : tcp_fields) {
        result["TCP"][kv.first] = kv.second;
    }
    result["TCP"]["modbus_tcp_offset"] = modbus_offset;

    // Modbus/TCP Header (MBAP)
    auto [mbtcp_fields, pdu_start, pdu_end] = ModbusTCPHeader::modbus_tcp_header_parser(frame, modbus_offset);
    for (auto &kv : mbtcp_fields) {
        result["ModbusTCP"][kv.first] = kv.second;
    }
    result["ModbusTCP"]["pdu_start"] = pdu_start;
    result["ModbusTCP"]["pdu_end"] = pdu_end;

    // classify (req/resp/error)
    string type = classify_req_res_error(ip_fields, frame, pdu_start, pdu_end, "185.175.0.3");
    result["Classification"]["type"] = type;

    // Modbus PDU
    try {
        auto mb_fields = ModbusHeader::parse(frame, pdu_start, pdu_end, type);
        for (auto &kv : mb_fields) {
            result["ModbusPDU"][kv.first] = kv.second;
        }
    } catch (const std::exception &e) {
        result["ModbusPDU"]["error"] = e.what();
    }

    return result;
}


// 아래는 추후 변경 (테스트 용도)
void run_modbus_process_test(const std::vector<std::string>& frames,
                             const std::vector<std::string>& expected_behavior,
                             const std::string& func_code) {

    cout << "\n============================\n";
    cout << "🧪 Modbus " << func_code << " 테스트 시작 (총 " << frames.size() << " 케이스)\n";
    cout << "============================\n";

    for (size_t i = 0; i < frames.size(); i++) {
        cout << "\n[Frame " << i << "] 예상 동작: " << expected_behavior[i] << "\n";
        cout << "HEX: " << frames[i] << "\n";
        vector<uint8_t> frame_bytes = hex_to_bytes(frames[i]);

        try {
            process_frame(frame_bytes);
            cout << "✅ 정상 처리 완료\n";
        } catch (const std::exception &e) {
            cout << "❌ 예외 발생: " << e.what() << "\n";
        }

        cout << "---------------------------------------------\n";
    }

    cout << "✅ Modbus " << func_code << " 테스트 완료 ✅\n";
}

int main() {
    // int number = 2;
    // Modbus/TCP Request, Response, Error frames
    // vector<string> req_data = {
    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 03 6d 40 00 40 06 c3 e4 b9 af 00 03 b9 af 00 05 e6 54 01 f6 a6 d0 cc 60 41 89 89 a6 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 77 32 eb 86 7f 00 03 00 00 00 06 01 01 00 19 00 01", // 0x01
    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 66 7e 40 00 40 06 60 d3 b9 af 00 03 b9 af 00 05 e6 5a 01 f6 9c 95 77 8a 9a ce 61 dd 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 a1 32 eb 86 aa 00 05 00 00 00 06 01 02 00 05 00 01", // 0X02
    //     "0242b9af00050242b9af0003080045000040d59940004006f1b7b9af0003b9af0005e65001f69f549c44247c6f42801801f6739900000101080a845b994b32eb8654000100000006010300230001", // 0x03

    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 06 01 04 00 23 00 02", // 0x04
    // };
    // vector<uint8_t> req_frame = hex_to_bytes(req_data[number]);
    
    // vector<string> res_data = {
    //     "02 42 b9 af 00 03 02 42 b9 af 00 05 08 00 45 00 00 3e 5b be 40 00 40 06 6b 95 b9 af 00 05 b9 af 00 03 01 f6 e6 54 41 89 89 a6 a6 d0 cc 6c 80 18 01 fd 73 97 00 00 01 01 08 0a 32 eb 86 80 84 5b 99 77 00 03 00 00 00 04 01 01 01 00", // 0x01
    //     "02 42 b9 af 00 03 02 42 b9 af 00 05 08 00 45 00 00 3e 6d 4f 40 00 40 06 5a 04 b9 af 00 05 b9 af 00 03 01 f6 e6 5a 9a ce 61 dd 9c 95 77 96 80 18 01 fd 73 97 00 00 01 01 08 0a 32 eb 86 ab 84 5b 99 a1 00 05 00 00 00 04 01 02 01 00", // 0X02
    //     "0242b9af00030242b9af000508004500003f56d440004006707eb9af0005b9af000301f6e650247c6f429f549c50801801fd739800000101080a32eb8654845b994b000100000005010303000900010019", // 0x03

    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 05 b9 af 00 03 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 07 01 04 04 11 11 22 22", // 0x04
    // };
    // vector<uint8_t> res_frame = hex_to_bytes(res_data[number]);

    // vector<string> err_data = {
    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 81 01", // exception 0x01
    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 82 02", // exception 0x02
    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 83 03", // exception 0x03
    
    
    //     "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 03 01 84 04", // exception 0x04
    // };
    // vector<uint8_t> err_frame = hex_to_bytes(err_data[number]);

    // string SCADA_IP = "185.175.0.3";

    // process_frame(req_frame);
    // process_frame(res_frame);
    // process_frame(err_frame);

    // json j = process_frame_json(req_frame);
    // std::cout << j.dump(4) << std::endl;


    run_modbus_process_test(modbus_0x03_testing, expected_0x03, "0x03");

    // cout << "========================================\n최종 실행 단계: Modbus PDU 파싱\n";
    return 0;
}
