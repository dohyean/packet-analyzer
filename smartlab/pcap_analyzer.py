import pandas as pd
from scapy.all import rdpcap, TCP, IP, Raw
import struct
from collections import defaultdict

# --- 1. 파일 경로 설정 ---
PCAPNG_FILE = 'capture.pcapng'
ASSET_IP_FILE = '자산IP.csv'
INPUT_MAPPING_FILE = '유선_Input.csv'
OUTPUT_MAPPING_FILE = '유선_Output.csv'
OUTPUT_ANALYSIS_FILE = 'output.txt'
OUTPUT_SUMMARY_FILE = 'summary.txt'

# --- 2. 매핑 데이터 로드 ---
try:
    # 'encoding' 옵션을 제거하여 자동 탐지
    df_asset_ip = pd.read_csv(ASSET_IP_FILE)
    df_input = pd.read_csv(INPUT_MAPPING_FILE)
    df_output = pd.read_csv(OUTPUT_MAPPING_FILE)

    ip_to_asset = {row['IP']: f"{row['자산명']} ({row['역할']})" for index, row in df_asset_ip.iterrows()}
    
    register_mappings = {}
    for index, row in df_input.iterrows():
        register_mappings[('coil', row['RegisterAddress'] - 1)] = row['Description']
    for index, row in df_output.iterrows():
        register_mappings[('holding', row['RegisterAddress'] - 40001)] = row['Description']
    print("✅ 매핑 정보 로딩 완료.")
except Exception as e:
    print(f"❌ 오류: CSV 파일 처리 중 문제 발생: {e}")
    exit()

modbus_func_codes = {
    1: "Read Coils", 3: "Read Holding Registers",
    5: "Write Single Coil", 6: "Write Single Register",
}

# --- 3. PCAP 파일 분석 및 파일 출력 ---
def analyze_pcap_to_files(pcap_file):
    print(f"--- {pcap_file} 파일 분석 시작 (결과는 파일로 저장됩니다) ---")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"❌ 오류: PCAP 파일 로딩 중 문제 발생: {e}")
        return

    total_packets = len(packets)
    total_bytes = 0
    protocol_counts = defaultdict(int)

    with open(OUTPUT_ANALYSIS_FILE, 'w', encoding='utf-8') as f_out:
        for i, pkt in enumerate(packets):
            total_bytes += len(pkt)
            protocol = "Other"
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_asset = ip_to_asset.get(src_ip, src_ip)
                dst_asset = ip_to_asset.get(dst_ip, dst_ip)
                meaningful_description = ""

                if TCP in pkt and (pkt[TCP].dport == 502 or pkt[TCP].sport == 502):
                    protocol = "Modbus/TCP"
                    if Raw in pkt and len(pkt[Raw].load) >= 7:
                        pdu = pkt[Raw].load
                        func_code = pdu[6]
                        is_response = (pkt[TCP].sport == 502)

                        if not is_response and func_code in modbus_func_codes:
                            if func_code in [1, 3] and len(pdu) >= 12:
                                addr, count = struct.unpack('>HH', pdu[7:11])
                                reg_type = 'coil' if func_code == 1 else 'holding'
                                desc = register_mappings.get((reg_type, addr), f"주소 {addr}")
                                meaningful_description = f"'{modbus_func_codes[func_code]}' 요청: '{desc}'부터 {count}개 읽기"
                            elif func_code == 5 and len(pdu) >= 11:
                                addr, value_raw = struct.unpack('>HH', pdu[7:11])
                                value = "ON" if value_raw == 0xff00 else "OFF"
                                desc = register_mappings.get(('coil', addr), f"주소 {addr}")
                                meaningful_description = f"'{modbus_func_codes[func_code]}' 요청: '{desc}' 상태를 [{value}]으로 변경"
                            elif func_code == 6 and len(pdu) >= 11:
                                addr, value = struct.unpack('>HH', pdu[7:11])
                                desc = register_mappings.get(('holding', addr), f"주소 {addr}")
                                meaningful_description = f"'{modbus_func_codes[func_code]}' 요청: '{desc}' 값을 [{value}]으로 설정"
                        elif is_response:
                            meaningful_description = f"'{modbus_func_codes.get(func_code, 'Unknown')}'에 대한 응답"

                elif TCP in pkt and (pkt[TCP].dport == 102 or pkt[TCP].sport == 102):
                    protocol = "S7COMM"
                    meaningful_description = "Siemens S7 통신"

                elif pkt.haslayer('ARP'):
                    protocol = "ARP"
                    if pkt.op == 1: meaningful_description = f"ARP 요청: {pkt.pdst}의 MAC 주소 문의"
                    else: meaningful_description = f"ARP 응답: {pkt.psrc}는 {pkt.hwsrc}에 있음"
                
                else: # TCP, UDP 등 기타 IP 프로토콜 식별
                    if pkt.haslayer(TCP):
                        protocol = 'TCP'
                    elif pkt.haslayer('UDP'):
                        protocol = 'UDP'
                    elif pkt.haslayer('ICMP'):
                        protocol = 'ICMP'
                
                protocol_counts[protocol] += 1
                
                if meaningful_description:
                    f_out.write(f"--- 패킷 #{i+1} ({pkt.time:.2f}s) ---\n")
                    f_out.write(f"{src_asset} -> {dst_asset}\n")
                    f_out.write(f"프로토콜: {protocol}\n")
                    f_out.write(f"의미: {meaningful_description}\n\n")

    # --- 4. 분석 요약 정보 파일로 저장 ---
    with open(OUTPUT_SUMMARY_FILE, 'w', encoding='utf-8') as f_sum:
        f_sum.write("="*40 + "\n")
        f_sum.write("📊 분석 결과 요약 (Analysis Summary)\n")
        f_sum.write("="*40 + "\n\n")
        f_sum.write("[전체 트래픽 정보]\n")
        f_sum.write(f"  - 총 패킷 수: {total_packets} 개\n")
        if total_bytes > 1024 * 1024:
            f_sum.write(f"  - 전체 트래픽 양: {total_bytes / (1024*1024):.2f} MB\n")
        elif total_bytes > 1024:
            f_sum.write(f"  - 전체 트래픽 양: {total_bytes / 1024:.2f} KB\n")
        else:
            f_sum.write(f"  - 전체 트래픽 양: {total_bytes} Bytes\n")
        f_sum.write("\n[프로토콜별 비율]\n")
        sorted_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
        for proto, count in sorted_protocols:
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            f_sum.write(f"  - {proto:<12}: {count:5d} 개 ({percentage:6.2f} %)\n")
        f_sum.write("\n" + "="*40 + "\n")
        
    print(f"✅ 분석 완료. 상세 결과는 {OUTPUT_ANALYSIS_FILE}, 요약 결과는 {OUTPUT_SUMMARY_FILE}에 저장되었습니다.")

# --- 5. 분석 실행 ---
if __name__ == "__main__":
    analyze_pcap_to_files(PCAPNG_FILE)