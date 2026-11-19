import os
import socket
import struct
import unittest

from dnscheck.protocol.stun import (
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    STUN_BINDING_RESPONSE,
    STUN_MAGIC_COOKIE,
    build_stun_binding_request,
    parse_stun_binding_response,
)


class TestSTUNProtocol(unittest.TestCase):
    def test_build_binding_request(self):
        txid, pkt = build_stun_binding_request()
        self.assertEqual(len(txid), 12)
        self.assertEqual(len(pkt), 20)
        msg_type, msg_len, cookie = struct.unpack("!HHI", pkt[:8])
        self.assertEqual(msg_type, 0x0001)
        self.assertEqual(msg_len, 0)
        self.assertEqual(cookie, STUN_MAGIC_COOKIE)

    def test_parse_xor_mapped_address_ipv4(self):
        txid = os.urandom(12)
        target_ip = "203.0.113.42"
        target_port = 54321

        xport = target_port ^ (STUN_MAGIC_COOKIE >> 16)
        (ip_int,) = struct.unpack("!I", socket.inet_aton(target_ip))
        xaddr = ip_int ^ STUN_MAGIC_COOKIE
        attr_val = struct.pack("!BBHI", 0, 0x01, xport, xaddr)
        attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(attr_val)) + attr_val
        resp = struct.pack("!HHI", STUN_BINDING_RESPONSE, len(attr), STUN_MAGIC_COOKIE) + txid + attr

        ip_out, port_out = parse_stun_binding_response(resp, expected_txid=txid)
        self.assertEqual(ip_out, target_ip)
        self.assertEqual(port_out, target_port)

    def test_parse_xor_mapped_address_ipv6(self):
        txid = os.urandom(12)
        target_ip = "2001:db8::1234"
        target_port = 40000

        xport = target_port ^ (STUN_MAGIC_COOKIE >> 16)
        xor_key = struct.pack("!I", STUN_MAGIC_COOKIE) + txid
        raw_v6 = socket.inet_pton(socket.AF_INET6, target_ip)
        xaddr = bytes(a ^ b for a, b in zip(raw_v6, xor_key))
        attr_val = struct.pack("!BBH", 0, 0x02, xport) + xaddr
        attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(attr_val)) + attr_val
        resp = struct.pack("!HHI", STUN_BINDING_RESPONSE, len(attr), STUN_MAGIC_COOKIE) + txid + attr

        ip_out, port_out = parse_stun_binding_response(resp, expected_txid=txid)
        self.assertEqual(ip_out, target_ip)
        self.assertEqual(port_out, target_port)

    def test_parse_mapped_address_fallback_and_txid_mismatch(self):
        txid = os.urandom(12)
        target_ip = "198.51.100.9"
        target_port = 12345
        attr_val = struct.pack("!BBH", 0, 0x01, target_port) + socket.inet_aton(target_ip)
        attr = struct.pack("!HH", ATTR_MAPPED_ADDRESS, len(attr_val)) + attr_val
        resp = struct.pack("!HHI", STUN_BINDING_RESPONSE, len(attr), STUN_MAGIC_COOKIE) + txid + attr

        ip_out, port_out = parse_stun_binding_response(resp, expected_txid=txid)
        self.assertEqual(ip_out, target_ip)
        self.assertEqual(port_out, target_port)

        with self.assertRaises(ValueError):
            parse_stun_binding_response(resp, expected_txid=b"\x00" * 12)


if __name__ == "__main__":
    unittest.main()
