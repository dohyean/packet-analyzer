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
    // Common Function
    // run_modbus_process_test(modbus_0x01_testing, expected_0x01, "0x01");
    // run_modbus_process_test(modbus_0x02_testing, expected_0x02, "0x02");
    // run_modbus_process_test(modbus_0x03_testing, expected_0x03, "0x03");
    // run_modbus_process_test(modbus_0x04_testing, expected_0x04, "0x04");
    // run_modbus_process_test(modbus_0x05_testing, expected_0x05, "0x05");
    // run_modbus_process_test(modbus_0x06_testing, expected_0x06, "0x06");

    // Serial Line Only Function
    // run_modbus_process_test(modbus_0x07_testing, expected_0x07, "0x07");
    run_modbus_process_test(modbus_0x08_testing, expected_0x08, "0x08");

    // cout << "========================================\n최종 실행 단계: Modbus PDU 파싱\n";
    return 0;
}
