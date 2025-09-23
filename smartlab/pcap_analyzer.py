import pandas as pd
from scapy.all import rdpcap, TCP, IP, Raw
import struct
from collections import defaultdict

# --- 1. 파일 경로 설정 ---
# 분석할 PCAPNG 파일 이름 (이 부분을 실제 파일명으로 변경하세요)
PCAPNG_FILE = 'capture.pcapng'

# CSV 파일 이름 (자산 및 레지스터 매핑 정보)
ASSET_IP_FILE = '자산IP.csv'
INPUT_MAPPING_FILE = '유선_Input.csv'
OUTPUT_MAPPING_FILE = '유선_Output.csv'

# --- 2. 매핑 데이터 로드 및 전처리 ---
try:
    # CSV 파일들을 UTF-8으로 읽기 시도, 실패 시 CP949로 읽음
    try:
        df_asset_ip = pd.read_csv(ASSET_IP_FILE)
        df_input = pd.read_csv(INPUT_MAPPING_FILE)
        df_output = pd.read_csv(OUTPUT_MAPPING_FILE)
    except UnicodeDecodeError:
        df_asset_ip = pd.read_csv(ASSET_IP_FILE, encoding='cp949')
        df_input = pd.read_csv(INPUT_MAPPING_FILE, encoding='cp949')
        df_output = pd.read_csv(OUTPUT_MAPPING_FILE, encoding='cp949')

    ip_to_asset = {row['IP']: f"{row['자산명']} ({row['역할']})" for index, row in df_asset_ip.iterrows()}
    
    register_mappings = {}
    for index, row in df_input.iterrows():
        # Input은 Coil (1-9999) 또는 Discrete Input (10001-19999)으로 가정
        # 여기서는 Coil로 가정하고 0-based index로 변환 (address - 1)
        register_mappings[('coil', row['RegisterAddress'] - 1)] = row['Description']

    for index, row in df_output.iterrows():
        # Output은 Holding Register (40001-49999)로 가정
        # 0-based index로 변환 (address - 40001)
        register_mappings[('holding', row['RegisterAddress'] - 40001)] = row['Description']

except Exception as e:
    print(f"오류: CSV 파일 처리 중 문제 발생: {e}")
    exit()

# Modbus Function Code 설명
modbus_func_codes = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
}

# --- 3. PCAP 파일 분석 함수 ---
def analyze_pcap(pcap_file):
    print(f"\n--- {pcap_file} 파일 상세 분석 시작 ---\n")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"오류: PCAP 파일 로딩 중 문제 발생: {e}")
        return

    total_packets = len(packets)
    total_bytes = 0
    protocol_counts = defaultdict(int)

    for i, pkt in enumerate(packets):
        total_bytes += len(pkt)
        protocol = "Other"

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_asset = ip_to_asset.get(src_ip, src_ip)
            dst_asset = ip_to_asset.get(dst_ip, dst_ip)
            meaningful_description = ""

            # 프로토콜 식별 및 카운트
            if TCP in pkt and (pkt[TCP].dport == 502 or pkt[TCP].sport == 502):
                protocol = "Modbus/TCP"
                if Raw in pkt:
                    pdu = pkt[Raw].load
                    if len(pdu) >= 7:
                        func_code = pdu[6]
                        is_response = 'Rsp' in pkt.summary() # 응답 여부 간단히 확인

                        if not is_response: # 요청 분석
                            if func_code in [1, 3] and len(pdu) >= 12:
                                addr = struct.unpack('>H', pdu[7:9])[0]
                                count = struct.unpack('>H', pdu[9:11])[0]
                                reg_type = 'coil' if func_code == 1 else 'holding'
                                desc = register_mappings.get((reg_type, addr), f"주소 {addr}")
                                meaningful_description = f"'{modbus_func_codes[func_code]}' 요청: '{desc}'부터 {count}개 읽기"
                            
                            elif func_code == 5 and len(pdu) >= 11:
                                addr = struct.unpack('>H', pdu[7:9])[0]
                                value = "ON" if struct.unpack('>H', pdu[9:11])[0] == 0xff00 else "OFF"
                                desc = register_mappings.get(('coil', addr), f"주소 {addr}")
                                meaningful_description = f"'{modbus_func_codes[func_code]}' 요청: '{desc}' 상태를 [{value}]으로 변경"
                            
                            elif func_code == 6 and len(pdu) >= 11:
                                addr = struct.unpack('>H', pdu[7:9])[0]
                                value = struct.unpack('>H', pdu[9:11])[0]
                                desc = register_mappings.get(('holding', addr), f"주소 {addr}")
                                meaningful_description = f"'{modbus_func_codes[func_code]}' 요청: '{desc}' 값을 [{value}]으로 설정"
                        else: # 응답 분석
                            meaningful_description = f"'{modbus_func_codes.get(func_code, 'Unknown')}'에 대한 응답"

            elif TCP in pkt and (pkt[TCP].dport == 102 or pkt[TCP].sport == 102):
                protocol = "S7COMM"
                meaningful_description = "Siemens S7 통신"
            
            elif pkt.haslayer('ARP'):
                protocol = "ARP"
                if pkt.op == 1: meaningful_description = f"ARP 요청: {pkt.pdst}의 MAC 주소 문의"
                else: meaningful_description = f"ARP 응답: {pkt.psrc}는 {pkt.hwsrc}에 있음"
            
            protocol_counts[protocol] += 1
            
            # 상세 분석 결과 출력
            if meaningful_description:
                print(f"--- 패킷 #{i+1} ({pkt.time:.2f}s) ---")
                print(f"{src_asset}  ->  {dst_asset}")
                print(f"프로토콜: {protocol}")
                print(f"의미: {meaningful_description}\n")

    # --- 4. 분석 요약 정보 출력 ---
    print("\n" + "="*40)
    print("📊 분석 결과 요약 (Analysis Summary)")
    print("="*40)

    print(f"\n[전체 트래픽 정보]")
    print(f"  - 총 패킷 수: {total_packets} 개")
    if total_bytes > 1024 * 1024:
        print(f"  - 전체 트래픽 양: {total_bytes / (1024*1024):.2f} MB")
    elif total_bytes > 1024:
        print(f"  - 전체 트래픽 양: {total_bytes / 1024:.2f} KB")
    else:
        print(f"  - 전체 트래픽 양: {total_bytes} Bytes")

    print("\n[프로토콜별 비율]")
    sorted_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
    for proto, count in sorted_protocols:
        percentage = (count / total_packets) * 100 if total_packets > 0 else 0
        print(f"  - {proto:<12}: {count:5d} 개 ({percentage:6.2f} %)")
    
    print("\n" + "="*40)

# --- 5. 분석 실행 ---
if __name__ == "__main__":
    analyze_pcap(PCAPNG_FILE)
    print("\n--- 모든 작업 종료 ---")