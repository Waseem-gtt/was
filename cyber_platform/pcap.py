"""Bounded classic-PCAP metadata analysis; no capture, payload export or network."""
import base64
import binascii
import hashlib
import ipaddress
import json
import struct

MAX_BYTES = 4 * 1024 * 1024
MAX_PACKETS = 5000
MAX_FLOWS = 1000
MAX_EXTENSIONS = 8
_MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 'microseconds', 1000000),
    b'\xa1\xb2\xc3\xd4': ('>', 'microseconds', 1000000),
    b'\x4d\x3c\xb2\xa1': ('<', 'nanoseconds', 1000000000),
    b'\xa1\xb2\x3c\x4d': ('>', 'nanoseconds', 1000000000),
}
LIMITATIONS = (
    'تحليل بيانات وصفية من classic PCAP كامل الحزم فقط؛ لا pcapng أو إعادة تجميع تدفقات '
    'أو فك TLS أو تصدير حمولة أو التقاط حي. يدعم Ethernet مع طبقتي VLAN أو raw IP، '
    'وIPv4/IPv6 وترويسات امتداد IPv6 محدودة. لا يتحقق من checksums ولا يثبت نشاطًا ضارًا. '
    'الحزم المجزأة لا تفسر كمنافذ نقل، والأنواع الأخرى تبقى مصنفة دون فك محتواها.'
)


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('Duplicate PCAP envelope field')
        value[key] = item
    return value


def _input(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('PCAP input exceeds 4 MiB or is not bytes')
    if data.lstrip().startswith(b'{'):
        try:
            envelope = json.loads(data, object_pairs_hook=_pairs)
            if not isinstance(envelope, dict) or set(envelope) != {'pcap_base64'} or not isinstance(envelope['pcap_base64'], str):
                raise ValueError('Use only pcap_base64 in the PCAP JSON envelope')
            capture = base64.b64decode(envelope['pcap_base64'], validate=True)
        except (UnicodeError, binascii.Error, RecursionError) as exc:
            raise ValueError('Invalid PCAP envelope or base64') from exc
        if len(capture) > MAX_BYTES:
            raise ValueError('Decoded PCAP exceeds 4 MiB')
        return capture, 'base64-json'
    return data, 'raw'


def _transport(protocol, packet, ipv6=False, fragmented=False):
    name = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 59: 'NO_NEXT_HEADER'}.get(protocol, 'IP_' + str(protocol))
    if fragmented:
        return name, None, None
    if protocol == 6:
        if len(packet) < 20:
            raise ValueError('Truncated TCP header')
        header_length = (packet[12] >> 4) * 4
        if header_length < 20 or header_length > len(packet):
            raise ValueError('Invalid TCP data offset')
        return name, *struct.unpack_from('!HH', packet)
    if protocol == 17:
        if len(packet) < 8:
            raise ValueError('Truncated UDP header')
        source, target, length = struct.unpack_from('!HHH', packet)
        if length < 8 or length != len(packet):
            raise ValueError('UDP length does not match the complete IP payload')
        return name, source, target
    if protocol in (1, 58):
        if (protocol == 58) != ipv6:
            return 'IP_' + str(protocol), None, None
        if len(packet) < 4:
            raise ValueError('Truncated ICMP header')
    if protocol == 59 and ipv6 and packet:
        raise ValueError('Unexpected IPv6 no-next-header payload')
    return name, None, None


def _ipv4(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError('Invalid or truncated IPv4 header')
    header_length = (packet[0] & 15) * 4
    total_length = struct.unpack_from('!H', packet, 2)[0]
    if header_length < 20 or header_length > total_length or total_length > len(packet):
        raise ValueError('Invalid or truncated IPv4 length')
    flags = struct.unpack_from('!H', packet, 6)[0]
    if flags & 0x8000:
        raise ValueError('Reserved IPv4 fragmentation flag')
    fragmented = bool(flags & 0x3fff)
    if fragmented and flags & 0x4000:
        raise ValueError('Contradictory IPv4 fragmentation flags')
    if flags & 0x2000 and (total_length - header_length) % 8:
        raise ValueError('Non-final IPv4 fragment must contain multiples of eight bytes')
    source = str(ipaddress.IPv4Address(packet[12:16]))
    target = str(ipaddress.IPv4Address(packet[16:20]))
    protocol, source_port, target_port = _transport(packet[9], packet[header_length:total_length], fragmented=fragmented)
    return source, target, protocol, source_port, target_port, total_length, fragmented


def _ipv6(packet):
    if len(packet) < 40 or packet[0] >> 4 != 6:
        raise ValueError('Invalid or truncated IPv6 header')
    payload_length = struct.unpack_from('!H', packet, 4)[0]
    total_length = 40 + payload_length
    if total_length > len(packet):
        raise ValueError('Truncated IPv6 payload')
    source = str(ipaddress.IPv6Address(packet[8:24]))
    target = str(ipaddress.IPv6Address(packet[24:40]))
    protocol, offset, fragmented, count = packet[6], 40, False, 0
    seen_fragment = False
    while protocol in (0, 43, 44, 51, 60):
        count += 1
        if count > MAX_EXTENSIONS or offset + 2 > total_length:
            raise ValueError('IPv6 extension chain exceeds limit or is truncated')
        following = packet[offset]
        if protocol == 44:
            if seen_fragment:
                raise ValueError('Duplicate IPv6 fragment header')
            seen_fragment = True
            length = 8
            if offset + length > total_length:
                raise ValueError('Truncated IPv6 fragment header')
            flags = struct.unpack_from('!H', packet, offset + 2)[0]
            if packet[offset + 1] != 0 or flags & 6:
                raise ValueError('Invalid IPv6 fragment reserved fields')
            if flags & 1 and (total_length - offset - length) % 8:
                raise ValueError('Non-final IPv6 fragment must contain multiples of eight bytes')
            fragmented = bool(flags & 0xfff9)
            # Non-first fragments contain arbitrary fragment data, not another
            # extension header even if the saved next-header number says so.
            if flags & 0xfff8:
                protocol, offset = following, offset + length
                break
        else:
            length = (packet[offset + 1] + 2) * 4 if protocol == 51 else (packet[offset + 1] + 1) * 8
            if protocol == 51 and length < 12:
                raise ValueError('Invalid IPv6 authentication header length')
        if offset + length > total_length:
            raise ValueError('IPv6 extension length exceeds payload')
        protocol, offset = following, offset + length
    name, source_port, target_port = _transport(protocol, packet[offset:total_length], ipv6=True, fragmented=fragmented)
    return source, target, name, source_port, target_port, total_length, fragmented


def _packet(data, link_type):
    if link_type == 101:
        if not data:
            raise ValueError('Empty raw IP packet')
        version = data[0] >> 4
        if version not in (4, 6):
            raise ValueError('Raw IP link requires IPv4 or IPv6')
        result = _ipv4(data) if version == 4 else _ipv6(data)
        if result[5] != len(data):
            raise ValueError('Raw IP record length does not match the IP packet')
        return result
    if len(data) < 14:
        raise ValueError('Truncated Ethernet header')
    ether_type = struct.unpack_from('!H', data, 12)[0]
    offset, tags = 14, 0
    while ether_type in (0x8100, 0x88a8, 0x9100):
        tags += 1
        if tags > 2 or offset + 4 > len(data):
            raise ValueError('Ethernet VLAN stack exceeds limit or is truncated')
        ether_type = struct.unpack_from('!H', data, offset + 2)[0]
        offset += 4
    if ether_type == 0x0800:
        return _ipv4(data[offset:])
    if ether_type == 0x86dd:
        return _ipv6(data[offset:])
    # Do not reinterpret unknown EtherTypes or 802.3 lengths as IP.
    return None, None, f'ETHERTYPE_{ether_type:04X}', None, None, 0, False


def analyze(data):
    """Parse a complete capture atomically and return aggregate metadata only."""
    capture, encoding = _input(data)
    if capture.startswith(b'\x0a\x0d\x0d\x0a'):
        raise ValueError('pcapng is not supported; use classic PCAP')
    if len(capture) < 24 or capture[:4] not in _MAGIC:
        raise ValueError('Invalid or truncated classic PCAP global header')
    endian, resolution, fraction_limit = _MAGIC[capture[:4]]
    major, minor, _, _, snaplen, link_type = struct.unpack_from(endian + 'HHiIII', capture, 4)
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_BYTES or link_type not in (1, 101):
        raise ValueError('Unsupported PCAP version, snaplen or link type')
    offset, count, captured_bytes, original_bytes = 24, 0, 0, 0
    flows, protocols, first, last = {}, {}, None, None
    while offset < len(capture):
        count += 1
        if count > MAX_PACKETS:
            raise ValueError('PCAP packet count exceeds 5000')
        if offset + 16 > len(capture):
            raise ValueError('Truncated PCAP packet record header')
        seconds, fraction, captured, original = struct.unpack_from(endian + 'IIII', capture, offset)
        offset += 16
        if fraction >= fraction_limit or not 0 < captured <= snaplen or captured > original or captured > len(capture) - offset:
            raise ValueError('Invalid PCAP timestamp, record length or truncated packet')
        if captured != original:
            raise ValueError('Snap-truncated packet capture is not supported')
        packet = capture[offset:offset + captured]
        offset += captured
        source, target, protocol, source_port, target_port, ip_bytes, fragmented = _packet(packet, link_type)
        key = (source, target, protocol, source_port, target_port)
        if key not in flows:
            if len(flows) >= MAX_FLOWS:
                raise ValueError('PCAP distinct flow count exceeds 1000')
            flows[key] = {'source': source, 'destination': target, 'protocol': protocol,
                          'source_port': source_port, 'destination_port': target_port,
                          'packets': 0, 'captured_bytes': 0, 'ip_bytes': 0, 'fragmented_packets': 0}
        flow = flows[key]
        flow['packets'] += 1
        flow['captured_bytes'] += captured
        flow['ip_bytes'] += ip_bytes
        flow['fragmented_packets'] += int(fragmented)
        protocols[protocol] = protocols.get(protocol, 0) + 1
        captured_bytes += captured
        original_bytes += original
        timestamp = (seconds, fraction)
        first = timestamp if first is None or timestamp < first else first
        last = timestamp if last is None or timestamp > last else last
    return {'schema': 'was.pcap-analysis/1', 'packet_count': count,
            'captured_bytes': captured_bytes, 'original_bytes': original_bytes,
            'link_type': link_type, 'link_name': 'Ethernet' if link_type == 1 else 'raw IP',
            'byte_order': 'little' if endian == '<' else 'big', 'timestamp_resolution': resolution,
            'time_range': {'first': list(first) if first else None, 'last': list(last) if last else None},
            'protocols': protocols, 'flows': list(flows.values()),
            'input_encoding': encoding, 'input_sha256': hashlib.sha256(data).hexdigest(),
            'capture_sha256': hashlib.sha256(capture).hexdigest(),
            'payload_exported': False, 'live_capture': False, 'checksums_verified': False,
            'limits': {'input_bytes': MAX_BYTES, 'packets': MAX_PACKETS, 'flows': MAX_FLOWS,
                       'ipv6_extensions': MAX_EXTENSIONS, 'vlan_tags': 2}, 'limitations': LIMITATIONS}


def sample():
    """Fixed synthetic RFC5737 metadata; never a live capture or real payload."""
    ethernet = bytes.fromhex('0200000000020200000000010800')
    ipv4 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 1, 0, 64, 17, 0,
                       ipaddress.IPv4Address('192.0.2.1').packed,
                       ipaddress.IPv4Address('198.51.100.2').packed)
    packet = ethernet + ipv4 + struct.pack('!HHHH', 53000, 53, 8, 0)
    return (struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            + struct.pack('<IIII', 1700000000, 123456, len(packet), len(packet)) + packet)
