import base64
import json
import secrets
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from dnscheck.detectors.dns_leak import evaluate_oast_vectors, parse_akahelp_txt_answers
from dnscheck.enricher.ip_intel import IPIntel
from dnscheck.protocol.dns_packet import TYPE_HTTPS, build_dns_query, parse_dns_response
from dnscheck.protocol.interactsh import (
    InteractshInteraction,
    aes_cfb128_decrypt,
    aes_cfb128_encrypt,
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    extract_ecs_from_raw_request,
    extract_ip_from_remote_address,
    generate_rsa_keypair,
    generate_rsa_keypair_pure_python,
    generate_xid,
    register_fastest_oast_session,
)


class _MockOASTHandler(BaseHTTPRequestHandler):
    """In-memory mock Interactsh server implementing /register, /poll, and /deregister."""

    sessions = {}
    deregistered = set()

    def log_message(self, format, *args):
        pass

    def _send_json(self, obj: dict, code: int = 200):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.path == "/register":
            cid = body["correlation-id"]
            secret = body["secret-key"]
            pub_pem = base64.b64decode(body["public-key"])
            self.__class__.sessions[cid] = {
                "secret": secret,
                "pub_pem": pub_pem,
            }
            self._send_json({"message": "registration successful"})
        elif self.path == "/deregister":
            cid = body["correlation-id"]
            self.__class__.deregistered.add(cid)
            self._send_json({"message": "deregistration successful"})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/poll":
            self._send_json({"error": "not found"}, 404)
            return
        qs = parse_qs(parsed.query)
        cid = qs.get("id", [""])[0]
        sess = self.__class__.sessions.get(cid)
        if not sess:
            self._send_json({"error": "unknown id"}, 400)
            return

        kp_pub = sess["client_kp"]
        q65_uid = sess["q65_uid"]
        aes_key = secrets.token_bytes(32)
        enc_aes_key = base64.b64encode(kp_pub.encrypt_oaep_sha256(aes_key)).decode("ascii")

        # Event 0 encrypted with modern AES-256-CTR (single-label QNAME-minimized uid)
        ev0 = {
            "protocol": "dns",
            "unique-id": q65_uid,
            "full-id": q65_uid,
            "q-type": "HTTPS",
            "remote-address": "223.5.5.5:49122",
            "raw-request": ";; OPT PSEUDOSECTION:\n; SUBNET: 114.114.114.0/24/0\n",
            "timestamp": "2026-11-19T06:15:00Z",
        }
        # Event 1 encrypted with legacy AES-256-CFB128 (multi-label prefix fallback)
        ev1 = {
            "protocol": "dns",
            "unique-id": f"{cid}9999999999xyz",
            "full-id": f"proxy-sni.{cid}9999999999xyz",
            "q-type": "A",
            "remote-address": "[2606:4700:4700::1111]:53011",
            "raw-request": "",
            "timestamp": "2026-11-19T06:15:01Z",
        }

        iv0 = secrets.token_bytes(16)
        ct0 = aes_ctr_encrypt(aes_key, iv0, json.dumps(ev0).encode("utf-8"))
        iv1 = secrets.token_bytes(16)
        ct1 = aes_cfb128_encrypt(aes_key, iv1, json.dumps(ev1).encode("utf-8"))
        enc_items = [
            base64.b64encode(iv0 + ct0).decode("ascii"),
            base64.b64encode(iv1 + ct1).decode("ascii"),
        ]

        self._send_json({"data": enc_items, "extra": [], "aes_key": enc_aes_key})


class TestInteractshAndOASTLeak(unittest.TestCase):
    def test_xid_and_parsers(self):
        xid = generate_xid()
        self.assertEqual(len(xid), 20)
        self.assertTrue(xid.isalnum() and xid.islower())

        self.assertEqual(extract_ip_from_remote_address("8.8.8.8:53124"), "8.8.8.8")
        self.assertEqual(extract_ip_from_remote_address("1.1.1.1"), "1.1.1.1")
        self.assertEqual(
            extract_ip_from_remote_address("[2400:3200::1]:40123"),
            "2400:3200::1",
        )
        self.assertIsNone(extract_ip_from_remote_address("not-an-ip"))

        self.assertEqual(
            extract_ecs_from_raw_request(";; OPT\n; SUBNET: 114.114.114.0/24/0\n"),
            "114.114.114.0/24",
        )
        self.assertEqual(
            extract_ecs_from_raw_request("; SUBNET: [240e:390::]/56/0"),
            "240e:390::/56",
        )
        self.assertIsNone(extract_ecs_from_raw_request("; SUBNET: 0.0.0.0/0/0"))

    def test_crypto_roundtrip_and_openssl_interop(self):
        kp_pure = generate_rsa_keypair_pure_python(1024)
        secret_msg = secrets.token_bytes(32)
        ct = kp_pure.encrypt_oaep_sha256(secret_msg)
        self.assertEqual(kp_pure.decrypt_oaep_sha256(ct), secret_msg)

        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        payload = b'{"protocol":"dns","q-type":"HTTPS","remote-address":"223.5.5.5:53"}'
        enc = aes_cfb128_encrypt(aes_key, iv, payload)
        self.assertEqual(aes_cfb128_decrypt(aes_key, iv, enc), payload)

        if shutil.which("openssl"):
            kp = generate_rsa_keypair(2048, prefer_openssl=True)
            with tempfile.NamedTemporaryFile(suffix=".pem") as f:
                f.write(kp.public_key_pem())
                f.flush()
                proc = subprocess.run(
                    [
                        "openssl",
                        "pkeyutl",
                        "-encrypt",
                        "-pubin",
                        "-inkey",
                        f.name,
                        "-pkeyopt",
                        "rsa_padding_mode:oaep",
                        "-pkeyopt",
                        "rsa_oaep_md:sha256",
                        "-pkeyopt",
                        "rsa_mgf1_md:sha256",
                    ],
                    input=aes_key,
                    capture_output=True,
                    check=True,
                )
            self.assertEqual(kp.decrypt_oaep_sha256(proc.stdout), aes_key)

    def test_mock_oast_session_lifecycle(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockOASTHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            sess = register_fastest_oast_session(custom_server=f"http://127.0.0.1:{port}")
            self.assertIsNotNone(sess)
            sub = sess.subdomain(tag="qtype65")
            self.assertTrue(sub.startswith(sess.correlation_id))
            q65_uid = sub.split(".")[0]
            _MockOASTHandler.sessions[sess.correlation_id]["client_kp"] = sess.keypair
            _MockOASTHandler.sessions[sess.correlation_id]["q65_uid"] = q65_uid

            events = sess.poll()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].tag, "qtype65")
            self.assertEqual(events[0].q_type, "HTTPS")
            self.assertEqual(events[0].remote_ip, "223.5.5.5")
            self.assertEqual(events[0].ecs_subnet, "114.114.114.0/24")

            self.assertEqual(events[1].tag, "proxy-sni")
            self.assertEqual(events[1].remote_ip, "2606:4700:4700::1111")

            self.assertTrue(sess.deregister())
            self.assertIn(sess.correlation_id, _MockOASTHandler.deregistered)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_type65_packet_and_akahelp_parser(self):
        txid, raw = build_dns_query("qtype65.test.oast.pro", qtype=TYPE_HTTPS)
        pkt = parse_dns_response(raw)
        self.assertEqual(pkt.txid, txid)
        self.assertEqual(pkt.questions[0][1], 65)

        ns_ip, ecs_cidr = parse_akahelp_txt_answers(
            ["ns172.217.34.12", "ecs114.114.114.0/24/24", "ip203.0.113.9"]
        )
        self.assertEqual(ns_ip, "172.217.34.12")
        self.assertEqual(ecs_cidr, "114.114.114.0/24")

    def test_oast_vector_leak_attribution(self):
        intel_map = {
            "223.5.5.5": IPIntel(ip="223.5.5.5", asn="AS37963", is_cn=True),
            "8.8.8.8": IPIntel(ip="8.8.8.8", asn="AS15169", is_cn=False),
        }
        base_meta = {
            "sys-v4": ("sys-v4.x.oast.pro", ["198.18.0.12"], True, 1.2),
            "sys-v6": ("sys-v6.x.oast.pro", [], False, 1.0),
            "qtype65": ("qtype65.x.oast.pro", [], False, 15.0),
            "udp-sys": ("udp-sys.x.oast.pro", [], False, 40.0),
            "direct-sni": ("direct-sni.x.oast.pro", ["198.18.0.13"], True, 120.0),
            "proxy-sni": ("proxy-sni.x.oast.pro", [], False, 150.0),
        }

        # Case 1: Concurrent race leak on udp-sys + Type-65 leak on qtype65
        interactions_leak = [
            InteractshInteraction("dns", "u", "qtype65.u", "qtype65", "HTTPS", "223.5.5.5"),
            InteractshInteraction("dns", "u", "udp-sys.u", "udp-sys", "TXT", "223.5.5.5"),
            InteractshInteraction("dns", "u", "udp-sys.u", "udp-sys", "TXT", "8.8.8.8"),
            InteractshInteraction("dns", "u", "proxy-sni.u", "proxy-sni", "A", "8.8.8.8"),
        ]
        probes, race_leak, q65_leak, bypass_leak = evaluate_oast_vectors(
            base_meta, interactions_leak, intel_map, proxy_active=True
        )
        self.assertTrue(race_leak)
        self.assertTrue(q65_leak)
        self.assertFalse(bypass_leak)

        # Case 2: HTTP Proxy only (no TUN) -> proxy-sni clean overseas, sys-v4/direct-sni leak to CN
        meta_http_proxy = dict(base_meta)
        meta_http_proxy["sys-v4"] = ("sys-v4.x.oast.pro", ["104.21.1.1"], False, 18.0)
        interactions_bypass = [
            InteractshInteraction("dns", "u", "sys-v4.u", "sys-v4", "A", "223.5.5.5"),
            InteractshInteraction("dns", "u", "proxy-sni.u", "proxy-sni", "A", "8.8.8.8"),
        ]
        _, race2, q65_2, bypass2 = evaluate_oast_vectors(
            meta_http_proxy, interactions_bypass, intel_map, proxy_active=True
        )
        self.assertFalse(race2)
        self.assertFalse(q65_2)
        self.assertTrue(bypass2)


if __name__ == "__main__":
    unittest.main()
