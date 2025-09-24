# 02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 3c d5 97 40 00 40 06 f1 bd b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 43 00 00 00 00 a0 02 fa f0 73 95 00 00 02 04 05 b4 04 02 08 0a 84 5b 99 4b 00 00 00 00 01 03 03 07
import struct

class EtherHeader:
    # mac 주소 포맷 (xx:xx:xx:xx:xx:xx)
    @staticmethod
    def format_mac(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)

    # 다음 protocol 이름 포맷 (우선 3가지에 대해서만 라벨링)
    @staticmethod
    def format_ether_type(etype: int) -> str:
        mapping = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
        }
        return mapping.get(etype, "Unknown")

    # ethernet header parser
    @staticmethod
    def ethernet_header_parser(frame_bytes: bytes):
        if len(frame_bytes) < 14:
            raise ValueError(f"14 byte보다 작음 : {len(frame_bytes)} byte")
        dst_mac = frame_bytes[0:6]
        src_mac = frame_bytes[6:12]
        ether_type = int.from_bytes(frame_bytes[12:14], "big")
        return dst_mac, src_mac, ether_type


# IPv4만 들어온다는 가정
class IPv4Header:
    # ip 주소 포맷 (xxx.xxx.xxx.xxx)
    @staticmethod
    def format_ip(ip_bytes: bytes) -> str:
        return ".".join(str(b) for b in ip_bytes)

    # 다음 protocol 이름 포맷
    @staticmethod
    def format_protocol(proto: int) -> str:
        mapping = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        return mapping.get(proto, "Unknown")

    # ipv4 header parser
    @staticmethod
    def ipv4_header_parser(frame_bytes: bytes, ip_offset: int = 14):
        if len(frame_bytes) < ip_offset + 20:
            raise ValueError(f"{ip_offset + 20} byte보다 작음 : {len(frame_bytes)} byte")

        v_ihl = frame_bytes[ip_offset]
        version = (v_ihl >> 4) & 0x0F
        ihl_word = v_ihl & 0x0F
        ihl_bytes = ihl_word * 4
        if version != 4:
            raise ValueError(f"IPv4가 아님 : version={version}")
        if ihl_bytes < 20:
            raise ValueError(f"IPv4 header가 20 byte보다 작음 : {ihl_bytes} byte")

        # TOS (현재는 dscp, ecn으로 구성됨)
        dscp_ecn = frame_bytes[ip_offset + 1]
        dscp = dscp_ecn>>2
        ecn = dscp_ecn & 0b11
        total_length, ident, flags, ttl, protocol, checksum = struct.unpack_from(
            "!HHHBBH", frame_bytes, ip_offset + 2
        )

        flags3 = (flags >> 13) & 0x7
        reserved = bool(flags3 & 0b100)
        df = bool(flags3 & 0b010)
        mf = bool(flags3 & 0b001)
        frag_offset_units = (flags & 0x1FFF)
        frag_offset_bytes = frag_offset_units * 8

        src_ip = frame_bytes[ip_offset + 12: ip_offset + 16]
        dst_ip = frame_bytes[ip_offset + 16: ip_offset + 20]

        options = b""
        if ihl_bytes > 20:
            options = frame_bytes[ip_offset + 20: ip_offset + ihl_bytes]
        options_hex = " ".join(f"{b:02x}" for b in options)

        tcp_offset = ip_offset + ihl_bytes

        fields = {
            "version": version,
            "ihl_bytes": ihl_bytes,
            "dscp": dscp,
            "ecn": ecn,
            "total_length": total_length,
            "identification": ident,
            "flags_reserved": reserved,
            "flags_df": df,
            "flags_mf": mf,
            "frag_offset_bytes": frag_offset_bytes,
            "ttl": ttl,
            "protocol": protocol,
            "checksum": checksum,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "options_byte": options,
            "options_hex": options_hex
        }

        return fields, tcp_offset

class TCPHeader:
    TCP_FLAG_BITS = ["CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"] # NS는 무시(주로 사용 X)

    # flag 포맷 (CWR|ECE|URG|ACK|PSH|RST|SYN|FIN|NS)
    @staticmethod
    def format_flags(flags_byte: int) -> str:
        order = ["NS"] + TCPHeader.TCP_FLAG_BITS  # NS 표시는 선택적
        return "|".join([k for k in order if flags_byte.get(k)])

    # TCP header parser
    @staticmethod
    def tcp_header_parser(frame_bytes: bytes, tcp_offset: int):
        if len(frame_bytes) < tcp_offset + 20:
            raise ValueError(f"{tcp_offset + 20} byte보다 작음 : {len(frame_bytes)} byte")


        src_port, dst_port, seq_num, ack_num, HL_flags, window, checksum, urg_ptr = \
            struct.unpack_from("!HHIIHHHH", frame_bytes, tcp_offset)

        data_offset_words = (HL_flags >> 12) & 0xF
        HL = data_offset_words * 4
        if HL < 20 or HL > 60:
            raise ValueError(f"Invalid TCP header length: {HL} byte")

        # Flags (NS 포함 표시)
        std_flags = HL_flags & 0x00FF
        flags = {name: bool(std_flags & (1 << (7 - i))) for i, name in enumerate(TCPHeader.TCP_FLAG_BITS)}
        ns = bool((HL_flags >> 8) & 0x01)
        flags_full = {"NS": ns, **flags}

        options = b""
        if HL > 20:
            options = frame_bytes[tcp_offset+20 : tcp_offset+HL]
        options_hex = " ".join(f"{b:02x}" for b in options)

        modbus_tcp_offset = tcp_offset + HL

        fields = {
            "src_port": src_port,
            "dst_port": dst_port,
            "sequence_number": seq_num,
            "ack_number": ack_num,
            "header_length": HL,
            "flags": flags_full,
            "window_size": window,
            "checksum": checksum,
            "urgent_pointer": urg_ptr,
            "options_byte": options,
            "options_hex": options_hex,
        }

        return fields, modbus_tcp_offset
    
class ModbusTCPHeader:
    # modbus/TCP parser
    @staticmethod
    def modbus_tcp_header_parser(frame_bytes: bytes, modbus_offset: int):
        if len(frame_bytes) < modbus_offset + 7:
            raise ValueError(f"{modbus_offset + 7} byte보다 작음 : {len(modbus_offset)} byte")
        transaction_id, protocol_id, length_field = struct.unpack_from("!HHH", frame_bytes, modbus_offset)
        unit_id = frame_bytes[modbus_offset + 6]

        pdu_length = length_field - 1

        pdu_start = modbus_offset + 7
        pdu_end = pdu_start + pdu_length

        fields = {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "length": length_field,
            "unit_id": unit_id,
            "pdu_length": pdu_length
        }

        return fields, pdu_start, pdu_end

class ModbusHeader:
    # Function Code 정의
    FUNCTION_SPECS = {
        0x01: [("start_addr", 2), ("quantity", 2)],
        0x02: [("start_addr", 2), ("quantity", 2)],
        0x03: [("start_addr", 2), ("quantity", 2)],
        0x04: [("start_addr", 2), ("quantity", 2)],
        0x05: [("coil_addr", 2), ("value", 2)],
        0x06: [("register_addr", 2), ("value", 2)],
        0x0F: [("start_addr", 2), ("quantity", 2), ("byte_count", 1)],
        0x10: [("start_addr", 2), ("quantity", 2), ("byte_count", 1)],
        0x11: []
    }
    
    # Function Code 이름 정의
    FUNCTION_NAMES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x11: "Report Slave ID",
    }

    # modbus parser
    @staticmethod
    def modbus_header_parser(frame_bytes: bytes, pdu_start: int, pdu_end: int):
        if len(frame_bytes) < pdu_end:
            raise ValueError(f"{pdu_end} byte보다 작음 : {len(frame_bytes)} byte")
        

        function_code = frame_bytes[pdu_start]
        fields = {
            "function_code": function_code,
            "function_name": ModbusHeader.FUNCTION_NAMES.get(function_code, "Unknown")
        }
        
        spec = ModbusHeader.FUNCTION_SPECS.get(function_code, [])
        offset = pdu_start + 1
        for field_name, size in spec:
            if offset + size > pdu_end:
                raise ValueError(f"예상되는 byte를 넘김")
            raw = frame_bytes[offset:offset+size]
            
            value = raw[0] if size == 1 else int.from_bytes(raw, "big")
            fields[field_name] = value
            offset += size
        
        if "byte_count" in fields:
            data_len = fields["byte_count"]
            data_raw = frame_bytes[offset:offset+data_len]
            fields["data_raw"] = " ".join(f"{b:02x}" for b in data_raw)

        return fields

# protocol data 출력
def print_modbus_protocol(hex_data):
    try:
        # 숫자는 hex_data 중 어떤 것을 선택할지 지정
        print(f"[{check_number}] 출력 결과")

        step = "hex → bytes 변환"
        # 공백 포함된 hex string → byte 변환
        frame = bytes.fromhex(hex_data)
        print(f"byte frame : {frame}")

        step = "Ethernet 파싱"
        # ethernet 결과 출력
        print(f"="*40)
        print(f"Ethernet 결과")
        dst, src, etype = EtherHeader.ethernet_header_parser(frame)
        print(f"  dst_mac    : {EtherHeader.format_mac(dst)}")
        print(f"  src_mac    : {EtherHeader.format_mac(src)}")
        print(f"  ether_type : 0x{etype:04x} ({EtherHeader.format_ether_type(etype)})")

        step = "IPv4 파싱"
        # ipv4 결과 출력
        print(f"="*40)
        print (f"IPv4 결과")
        ip_felds, tcp_offset = IPv4Header.ipv4_header_parser(frame)
        print(f"  version           : {ip_felds['version']}")
        print(f"  ihl_bytes         : {ip_felds['ihl_bytes']}")
        print(f"  dscp              : {ip_felds['dscp']}")
        print(f"  ecn               : {ip_felds['ecn']}")
        print(f"  total_length      : {ip_felds['total_length']}")
        print(f"  identification    : {ip_felds['identification']}")
        print(f"  flags_reserved    : {ip_felds['flags_reserved']}")
        print(f"  flags_df          : {ip_felds['flags_df']}")
        print(f"  flags_mf          : {ip_felds['flags_mf']}")
        print(f"  frag_offset_bytes : {ip_felds['frag_offset_bytes']}")
        print(f"  ttl               : {ip_felds['ttl']}")
        print(f"  protocol          : {ip_felds['protocol']} ({IPv4Header.format_protocol(ip_felds['protocol'])})")
        print(f"  checksum          : 0x{ip_felds['checksum']:04x}")
        print(f"  src_ip            : {IPv4Header.format_ip(ip_felds['src_ip'])}")
        print(f"  dst_ip            : {IPv4Header.format_ip(ip_felds['dst_ip'])}")
        print(f"  options           : {ip_felds['options_hex']}")
        print(f"  tcp_offset        : {tcp_offset}")

        step = "TCP 파싱"
        # TCP 결과 출력
        print(f"="*40)
        print(f"TCP 결과")
        tcp_fields, modbus_tcp_offset = TCPHeader.tcp_header_parser(frame, tcp_offset)
        print(f"  src_port         : {(tcp_fields['src_port'])}")
        print(f"  dst_port         : {(tcp_fields['dst_port'])}")
        print(f"  seq_number       : 0x{tcp_fields['sequence_number']:04x}")
        print(f"  ack_number       : 0x{tcp_fields['ack_number']:04x}")
        print(f"  header_length    : {tcp_fields['header_length']}")
        flags = TCPHeader.format_flags(tcp_fields['flags']) if 'flags' in tcp_fields else ""
        print(f"  flags            : {flags}")
        print(f"  window_size      : 0x{tcp_fields['window_size']:04x}")
        print(f"  checksum         : 0x{tcp_fields['checksum']:04x}")
        print(f"  urgent_pointer   : {tcp_fields['urgent_pointer']}")
        print(f"  options          : {tcp_fields['options_hex']}")
        print(f"  mobus/TCP offset : {modbus_tcp_offset}")

        step = "Modbus/TCP 헤더 파싱"
        # modbus/TCP 결과 출력
        print(f"="*40)
        print(f"modbus/TCP 결과")
        modbus_tcp_fields, pdu_start, pdu_end = ModbusTCPHeader.modbus_tcp_header_parser(frame, modbus_tcp_offset)
        print(f"  Transaction ID : {modbus_tcp_fields['transaction_id']}")
        print(f"  Protocol ID    : {modbus_tcp_fields['protocol_id']}")
        print(f"  Length         : {modbus_tcp_fields['length']}")
        print(f"  Unit ID        : {modbus_tcp_fields['unit_id']}")
        print(f"  PDU length     : {modbus_tcp_fields['pdu_length']}")
        print(f"  PDU start      : {pdu_start}")
        print(f"  PDU end        : {pdu_end}")

        step = "Modbus PDU 파싱"
        # modbus pdu 결과 출력
        print(f"="*40)
        print(f"modbus pdu 결과")
        modbus_fields = ModbusHeader.modbus_header_parser(frame, pdu_start, pdu_end)
        for k, v in modbus_fields.items():
            print(f"  {k:15}: {v}")
            
    except Exception as e:
        print(f"오류 발생 : {e}")
    finally:
        print("="*40)
        print(f"최종 실행 단계: {step}")


# 추가해야하는 api : 추출된 데이터 csv 변환 api


# 예시
hex_data = [
    "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 3c d5 97 40 00 40 06 f1 bd b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 43 00 00 00 00 a0 02 fa f0 73 95 00 00 02 04 05 b4 04 02 08 0a 84 5b 99 4b 00 00 00 00 01 03 03 07", # TCP
    "02 42 b9 af 00 05 02 42 b9 af 00 03 08 00 45 00 00 40 d5 99 40 00 40 06 f1 b7 b9 af 00 03 b9 af 00 05 e6 50 01 f6 9f 54 9c 44 24 7c 6f 42 80 18 01 f6 73 99 00 00 01 01 08 0a 84 5b 99 4b 32 eb 86 54 00 01 00 00 00 06 01 03 00 23 00 01", # modbus
    "0242b9af00050242b9af0003080045000040d59940004006f1b7b9af0003b9af0005e65001f69f549c44247c6f42801801f6739900000101080a845b994b32eb8654000100000006010300230001", # modbus (hex)
    "\x02\x42\xb9\xaf\x00\x05\x02\x42\xb9\xaf\x00\x03\x08\x00\x45\x00\x00\x40\xd5\x99\x40\x00\x40\x06\xf1\xb7\xb9\xaf\x00\x03\xb9\xaf\x00\x05\xe6\x50\x01\xf6\x9f\x54\x9c\x44\x24\x7c\x6f\x42\x80\x18\x01\xf6\x73\x99\x00\x00\x01\x01\x08\x0a\x84\x5b\x99\x4b\x32\xeb\x86\x54\x00\x01\x00\x00\x00\x06\x01\x03\x00\x23\x00\x01" # modbus 해당 데이터 전처리 필요 
]
check_number = 1

print_modbus_protocol(hex_data[check_number])
