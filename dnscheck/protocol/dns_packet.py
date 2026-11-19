"""
Pure-Python RFC 1035 DNS wire-format encoder & decoder with EDNS0 (RFC 6891)
and EDNS Client Subnet / ECS (RFC 7871) support.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# DNS Record Types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_OPT = 41
TYPE_SVCB = 64
TYPE_HTTPS = 65
TYPE_ANY = 255

TYPE_NAMES: Dict[int, str] = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_PTR: "PTR",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_OPT: "OPT",
    TYPE_SVCB: "SVCB",
    TYPE_HTTPS: "HTTPS",
    TYPE_ANY: "ANY",
}

NAME_TO_TYPE: Dict[str, int] = {v: k for k, v in TYPE_NAMES.items()}

# DNS Classes
CLASS_IN = 1
CLASS_CH = 3  # Chaos class (e.g., whoami.cloudflare)

# RCODE definitions
RCODE_NAMES: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# EDNS0 Option Codes
EDNS_OPT_ECS = 8  # RFC 7871 Client Subnet


@dataclass
class ECSInfo:
    """Parsed EDNS Client Subnet (RFC 7871) option."""
    family: int  # 1 = IPv4, 2 = IPv6
    source_prefix_len: int
    scope_prefix_len: int
    address: str

    def to_dict(self) -> dict:
        return {
            "family": "IPv4" if self.family == 1 else ("IPv6" if self.family == 2 else str(self.family)),
            "source_prefix_len": self.source_prefix_len,
            "scope_prefix_len": self.scope_prefix_len,
            "address": self.address,
            "cidr": f"{self.address}/{self.source_prefix_len}",
        }


@dataclass
class DNSRecord:
    """Decoded DNS resource record."""
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: str
    raw_rdata: bytes = field(default=b"", repr=False)
    ecs: Optional[ECSInfo] = None

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "type": self.type_name,
            "ttl": self.ttl,
            "data": self.rdata,
        }
        if self.ecs:
            d["ecs"] = self.ecs.to_dict()
        return d


@dataclass
class DNSPacket:
    """Decoded DNS response message."""
    txid: int
    flags: int
    rcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    ad: bool  # Authentic Data (DNSSEC validated)
    cd: bool  # Checking Disabled
    questions: List[Tuple[str, int, int]]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]
    ecs_response: Optional[ECSInfo] = None
    edns_udp_size: Optional[int] = None
    edns_do_bit: bool = False

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE_{self.rcode}")

    @property
    def ip_answers(self) -> List[str]:
        """Return all A and AAAA record strings from the answer section."""
        return [r.rdata for r in self.answers if r.rtype in (TYPE_A, TYPE_AAAA)]

    @property
    def txt_answers(self) -> List[str]:
        """Return all TXT record strings from the answer section."""
        return [r.rdata for r in self.answers if r.rtype == TYPE_TXT]

    def to_dict(self) -> dict:
        return {
            "txid": self.txid,
            "rcode": self.rcode_name,
            "flags": {
                "aa": self.aa,
                "tc": self.tc,
                "rd": self.rd,
                "ra": self.ra,
                "ad": self.ad,
                "cd": self.cd,
                "do": self.edns_do_bit,
            },
            "answers": [r.to_dict() for r in self.answers],
            "authorities": [r.to_dict() for r in self.authorities],
            "ecs": self.ecs_response.to_dict() if self.ecs_response else None,
        }


def encode_dns_name(domain: str) -> bytes:
    """Encode a domain name into RFC 1035 label format."""
    domain = domain.strip(".")
    if not domain:
        return b"\x00"
    parts = domain.split(".")
    out = bytearray()
    for label in parts:
        encoded = label.encode("idna")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode a domain name from DNS wire format supporting RFC 1035 pointer compression (0xC0).
    Returns (decoded_domain, next_offset).
    """
    labels: List[str] = []
    jumped = False
    orig_next_offset = offset
    visited_Offsets = set()
    max_steps = 128
    steps = 0

    while steps < max_steps:
        steps += 1
        if offset >= len(data):
            raise ValueError("Truncated DNS packet while decoding domain name")
        length = data[offset]

        if length == 0:
            offset += 1
            if not jumped:
                orig_next_offset = offset
            break

        # Check compression pointer (top two bits 11 -> 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in visited_Offsets or pointer >= len(data):
                raise ValueError(f"Invalid or cyclic DNS compression pointer: {pointer}")
            visited_Offsets.add(pointer)
            if not jumped:
                orig_next_offset = offset + 2
                jumped = True
            offset = pointer
        elif (length & 0xC0) == 0:
            offset += 1
            if offset + length > len(data):
                raise ValueError("Truncated DNS label content")
            label_bytes = data[offset : offset + length]
            try:
                labels.append(label_bytes.decode("idna"))
            except Exception:
                labels.append(label_bytes.decode("latin1", errors="replace"))
            offset += length
            if not jumped:
                orig_next_offset = offset
        else:
            raise ValueError(f"Unsupported DNS label type bits: 0x{length:02x}")

    return ".".join(labels), orig_next_offset


def build_ecs_option(client_ip: str, source_prefix_len: Optional[int] = None) -> bytes:
    """
    Build an RFC 7871 EDNS Client Subnet (Option Code 8) payload.
    Format:
      Option-Code: 2 bytes (8)
      Option-Length: 2 bytes
      Family: 2 bytes (1=IPv4, 2=IPv6)
      Source Prefix-Length: 1 byte
      Scope Prefix-Length: 1 byte (0 in queries)
      Address: variable bytes (truncated to ceil(source_prefix_len / 8))
    """
    ip_obj = ipaddress.ip_address(client_ip)
    if ip_obj.version == 4:
        family = 1
        prefix = 24 if source_prefix_len is None else source_prefix_len
    else:
        family = 2
        prefix = 56 if source_prefix_len is None else source_prefix_len

    packed_ip = ip_obj.packed
    num_bytes = (prefix + 7) // 8
    addr_bytes = bytearray(packed_ip[:num_bytes])
    # Mask trailing bits if prefix is not a multiple of 8
    rem_bits = prefix % 8
    if rem_bits != 0 and num_bytes > 0:
        mask = (0xFF << (8 - rem_bits)) & 0xFF
        addr_bytes[-1] &= mask

    ecs_data = struct.pack("!HBB", family, prefix, 0) + bytes(addr_bytes)
    return struct.pack("!HH", EDNS_OPT_ECS, len(ecs_data)) + ecs_data


def parse_ecs_option(opt_data: bytes) -> Optional[ECSInfo]:
    """Parse an RFC 7871 EDNS Client Subnet option payload."""
    if len(opt_data) < 4:
        return None
    family, src_prefix, scope_prefix = struct.unpack("!HBB", opt_data[:4])
    addr_part = opt_data[4:]
    if family == 1:
        padded = addr_part.ljust(4, b"\x00")[:4]
        addr_str = socket.inet_ntop(socket.AF_INET, padded)
    elif family == 2:
        padded = addr_part.ljust(16, b"\x00")[:16]
        addr_str = socket.inet_ntop(socket.AF_INET6, padded)
    else:
        addr_str = addr_part.hex()
    return ECSInfo(
        family=family,
        source_prefix_len=src_prefix,
        scope_prefix_len=scope_prefix,
        address=addr_str,
    )


def build_dns_query(
    domain: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    txid: Optional[int] = None,
    rd: bool = True,
    ad: bool = True,
    cd: bool = False,
    use_edns: bool = True,
    edns_do: bool = False,
    edns_udp_size: int = 4096,
    ecs_ip: Optional[str] = None,
    ecs_prefix: Optional[int] = None,
) -> Tuple[int, bytes]:
    """
    Build a raw wire-format DNS query packet.
    Returns (transaction_id, raw_packet_bytes).
    """
    if txid is None:
        txid = random.randint(1, 0xFFFF)

    # Flags: Standard query (QR=0, Opcode=0)
    flags = 0
    if rd:
        flags |= 1 << 8  # Recursion Desired
    if ad:
        flags |= 1 << 5  # Authentic Data
    if cd:
        flags |= 1 << 4  # Checking Disabled

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1 if (use_edns or ecs_ip or edns_do) else 0

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    question = encode_dns_name(domain) + struct.pack("!HH", qtype, qclass)

    additional = b""
    if arcount == 1:
        # Build OPT Pseudo-RR (RFC 6891)
        # Name: root (0x00)
        # Type: 41 (OPT)
        # Class: UDP payload size (e.g. 4096)
        # TTL: Extended RCODE (1B) | Version (1B) | Flags (2B, bit 15 is DO)
        opt_flags = (1 << 15) if edns_do else 0
        opt_ttl = opt_flags  # Extended RCODE=0, Version=0
        opt_rdata = b""
        if ecs_ip:
            opt_rdata += build_ecs_option(ecs_ip, ecs_prefix)
        additional = (
            b"\x00"
            + struct.pack("!HHIH", TYPE_OPT, edns_udp_size, opt_ttl, len(opt_rdata))
            + opt_rdata
        )

    return txid, header + question + additional


def _decode_rdata(rtype: int, rclass: int, data: bytes, rdata_offset: int, rdlength: int) -> Tuple[str, Optional[ECSInfo]]:
    """Decode resource record payload into human-readable string and optional ECSInfo."""
    raw = data[rdata_offset : rdata_offset + rdlength]
    ecs_info: Optional[ECSInfo] = None

    if rtype == TYPE_A and len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw), None
    if rtype == TYPE_AAAA and len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw), None
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        target, _ = decode_dns_name(data, rdata_offset)
        return target, None
    if rtype == TYPE_TXT:
        # TXT records consist of one or more <character-string> (1-byte length + bytes)
        idx = 0
        parts = []
        while idx < len(raw):
            slen = raw[idx]
            idx += 1
            parts.append(raw[idx : idx + slen].decode("utf-8", errors="replace"))
            idx += slen
        return "".join(parts), None
    if rtype == TYPE_SOA:
        mname, pos = decode_dns_name(data, rdata_offset)
        rname, pos = decode_dns_name(data, pos)
        if pos + 20 <= len(data):
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos : pos + 20])
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}", None
        return f"{mname} {rname}", None
    if rtype == TYPE_OPT:
        # Parse EDNS options inside OPT RDATA
        idx = 0
        opt_summaries = []
        while idx + 4 <= len(raw):
            ocode, olen = struct.unpack("!HH", raw[idx : idx + 4])
            idx += 4
            oval = raw[idx : idx + olen]
            idx += olen
            if ocode == EDNS_OPT_ECS:
                ecs_info = parse_ecs_option(oval)
                if ecs_info:
                    opt_summaries.append(
                        f"ECS={ecs_info.address}/{ecs_info.source_prefix_len}(scope:/{ecs_info.scope_prefix_len})"
                    )
            else:
                opt_summaries.append(f"OPT_{ocode}({ len(oval) }B)")
        return ", ".join(opt_summaries) if opt_summaries else "EDNS0", ecs_info

    return raw.hex(), None


def parse_dns_response(data: bytes) -> DNSPacket:
    """Decode a wire-format DNS response packet into a DNSPacket object."""
    if len(data) < 12:
        raise ValueError(f"DNS packet too short ({len(data)} bytes)")

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    aa = bool((flags >> 10) & 1)
    tc = bool((flags >> 9) & 1)
    rd = bool((flags >> 8) & 1)
    ra = bool((flags >> 7) & 1)
    ad = bool((flags >> 5) & 1)
    cd = bool((flags >> 4) & 1)

    offset = 12
    questions: List[Tuple[str, int, int]] = []
    for _ in range(qdcount):
        qname, offset = decode_dns_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Truncated DNS question section")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append((qname, qtype, qclass))

    def read_rr_section(count: int) -> List[DNSRecord]:
        nonlocal offset
        records: List[DNSRecord] = []
        for _ in range(count):
            if offset >= len(data):
                break
            rname, offset = decode_dns_name(data, offset)
            if offset + 10 > len(data):
                raise ValueError("Truncated DNS resource record header")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(data):
                raise ValueError("Truncated DNS resource record data")
            rdata_str, ecs_info = _decode_rdata(rtype, rclass, data, offset, rdlength)
            raw_rdata = data[offset : offset + rdlength]
            offset += rdlength
            records.append(
                DNSRecord(
                    name=rname,
                    rtype=rtype,
                    rclass=rclass,
                    ttl=ttl,
                    rdata=rdata_str,
                    raw_rdata=raw_rdata,
                    ecs=ecs_info,
                )
            )
        return records

    answers = read_rr_section(ancount)
    authorities = read_rr_section(nscount)
    additionals = read_rr_section(arcount)

    ecs_response: Optional[ECSInfo] = None
    edns_udp_size: Optional[int] = None
    edns_do_bit = False

    for rr in additionals:
        if rr.rtype == TYPE_OPT:
            edns_udp_size = rr.rclass
            edns_do_bit = bool(rr.ttl & 0x8000)
            if rr.ecs:
                ecs_response = rr.ecs

    return DNSPacket(
        txid=txid,
        flags=flags,
        rcode=rcode,
        aa=aa,
        tc=tc,
        rd=rd,
        ra=ra,
        ad=ad,
        cd=cd,
        questions=questions,
        answers=answers,
        authorities=authorities,
        additionals=additionals,
        ecs_response=ecs_response,
        edns_udp_size=edns_udp_size,
        edns_do_bit=edns_do_bit,
    )
