import socket
import struct
import unittest

from dnscheck.protocol.dns_packet import (
    CLASS_IN,
    TYPE_A,
    TYPE_AAAA,
    TYPE_OPT,
    TYPE_TXT,
    build_dns_query,
    build_ecs_option,
    decode_dns_name,
    encode_dns_name,
    parse_dns_response,
    parse_ecs_option,
)


class TestDNSPacket(unittest.TestCase):
    def test_encode_decode_name(self):
        encoded = encode_dns_name("www.google.com")
        self.assertEqual(encoded, b"\x03www\x06google\x03com\x00")
        decoded, next_off = decode_dns_name(encoded, 0)
        self.assertEqual(decoded, "www.google.com")
        self.assertEqual(next_off, len(encoded))

    def test_decode_compressed_pointer(self):
        # Header (12 bytes placeholder) + "sub.example.com\0" at offset 12 + pointer to offset 16 ("example.com")
        buf = bytearray(b"\x00" * 12)
        name1 = encode_dns_name("sub.example.com")
        buf.extend(name1)
        # Pointer to offset 12 + 4 = 16 ("example.com")
        ptr_offset = len(buf)
        buf.extend(b"\x04mail\xc0\x10")
        decoded, next_off = decode_dns_name(bytes(buf), ptr_offset)
        self.assertEqual(decoded, "mail.example.com")
        self.assertEqual(next_off, len(buf))

    def test_ecs_option_ipv4_and_ipv6_roundtrip(self):
        opt_v4 = build_ecs_option("114.114.114.55", 24)
        ocode, olen = struct.unpack("!HH", opt_v4[:4])
        self.assertEqual(ocode, 8)
        parsed_v4 = parse_ecs_option(opt_v4[4 : 4 + olen])
        self.assertIsNotNone(parsed_v4)
        self.assertEqual(parsed_v4.family, 1)
        self.assertEqual(parsed_v4.source_prefix_len, 24)
        self.assertEqual(parsed_v4.address, "114.114.114.0")

        opt_v6 = build_ecs_option("2400:3200:baba::1", 48)
        _, olen6 = struct.unpack("!HH", opt_v6[:4])
        parsed_v6 = parse_ecs_option(opt_v6[4 : 4 + olen6])
        self.assertIsNotNone(parsed_v6)
        self.assertEqual(parsed_v6.family, 2)
        self.assertEqual(parsed_v6.source_prefix_len, 48)
        self.assertEqual(parsed_v6.address, "2400:3200:baba::")

    def test_build_query_and_parse_synthetic_response(self):
        txid, query_bytes = build_dns_query(
            "example.com",
            qtype=TYPE_A,
            edns_do=True,
            ecs_ip="223.5.5.5",
            ecs_prefix=24,
        )
        # Parse the query itself as a packet first
        q_pkt = parse_dns_response(query_bytes)
        self.assertEqual(q_pkt.txid, txid)
        self.assertEqual(q_pkt.questions[0][0], "example.com")
        self.assertTrue(q_pkt.edns_do_bit)
        self.assertIsNotNone(q_pkt.ecs_response)
        self.assertEqual(q_pkt.ecs_response.address, "223.5.5.0")

        # Now synthesize a full response with A, AAAA, TXT, and OPT records
        flags = 0x81A0  # QR=1, RD=1, RA=1, AD=1
        header = struct.pack("!HHHHHH", txid, flags, 1, 3, 0, 1)
        question = encode_dns_name("example.com") + struct.pack("!HH", TYPE_A, CLASS_IN)
        # Answer 1: A (93.184.216.34) using compression pointer 0xC00C
        ans_a = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, CLASS_IN, 300, 4) + socket.inet_aton("93.184.216.34")
        # Answer 2: AAAA
        v6_bytes = socket.inet_pton(socket.AF_INET6, "2606:2800:220:1::248")
        ans_aaaa = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_AAAA, CLASS_IN, 300, 16) + v6_bytes
        # Answer 3: TXT
        txt_payload = b"\x0chello-dnssec"
        ans_txt = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_TXT, CLASS_IN, 120, len(txt_payload)) + txt_payload
        # Additional: OPT with DO=1 and ECS
        ecs_opt = build_ecs_option("223.5.5.0", 24)
        opt_rr = b"\x00" + struct.pack("!HHIH", TYPE_OPT, 4096, 0x8000, len(ecs_opt)) + ecs_opt

        raw_resp = header + question + ans_a + ans_aaaa + ans_txt + opt_rr
        pkt = parse_dns_response(raw_resp)

        self.assertEqual(pkt.txid, txid)
        self.assertTrue(pkt.ad)
        self.assertTrue(pkt.ra)
        self.assertTrue(pkt.edns_do_bit)
        self.assertEqual(pkt.ip_answers, ["93.184.216.34", "2606:2800:220:1::248"])
        self.assertEqual(pkt.txt_answers, ["hello-dnssec"])
        self.assertIsNotNone(pkt.ecs_response)
        self.assertEqual(pkt.ecs_response.address, "223.5.5.0")


if __name__ == "__main__":
    unittest.main()
