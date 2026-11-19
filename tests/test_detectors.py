import json
import threading
import unittest
import urllib.request

from dnscheck.cli.renderer import display_width, render_table, strip_ansi
from dnscheck.detectors.ai_services import SANCTIONED_PLUS_HK_CCS, classify_ai_probe
from dnscheck.detectors.pollution_bench import classify_pollution_result, is_bogon_or_forged_ip
from dnscheck.enricher.ip_intel import IPIntel, classify_local_or_known_ip, is_fake_ip
from dnscheck.protocol.transports import DNSQueryResult
from dnscheck.web.server import create_server


class TestDetectorsAndUI(unittest.TestCase):
    def test_fake_ip_and_local_classification(self):
        self.assertTrue(is_fake_ip("198.18.0.1"))
        self.assertTrue(is_fake_ip("198.19.255.254"))
        self.assertFalse(is_fake_ip("8.8.8.8"))

        fake_intel = classify_local_or_known_ip("198.18.12.34")
        self.assertIsNotNone(fake_intel)
        self.assertTrue(fake_intel.is_fake_ip)

        loop_intel = classify_local_or_known_ip("127.0.0.1")
        self.assertTrue(loop_intel.is_loopback)

        lan_intel = classify_local_or_known_ip("192.168.1.1")
        self.assertTrue(lan_intel.is_private)

        ali_intel = classify_local_or_known_ip("223.5.5.5")
        self.assertTrue(ali_intel.is_cn)
        self.assertEqual(ali_intel.asn, "AS37963")

        cf_intel = classify_local_or_known_ip("1.1.1.1")
        self.assertFalse(cf_intel.is_cn)
        self.assertEqual(cf_intel.asn, "AS13335")

    def test_pollution_detection_classification(self):
        # Bogon / blackhole
        self.assertIsNotNone(is_bogon_or_forged_ip("0.0.0.0", "www.google.com"))
        self.assertIsNotNone(is_bogon_or_forged_ip("127.0.0.1", "www.google.com"))
        # Cross-brand forged Facebook IP returned for google
        self.assertIsNotNone(is_bogon_or_forged_ip("31.13.71.36", "www.google.com"))
        self.assertIsNone(is_bogon_or_forged_ip("142.250.190.4", "www.google.com"))

        # Classify FAKE_IP
        res_fake = DNSQueryResult(
            server="127.0.0.1",
            protocol="udp",
            domain="www.google.com",
            qtype="A",
            success=True,
            latency_ms=1.2,
            answers=["198.18.0.55"],
        )
        c_fake = classify_pollution_result("www.google.com", "系统", "127.0.0.1", res_fake, ["142.250.1.1"], {"AS15169"}, {})
        self.assertEqual(c_fake.status, "FAKE_IP")

        # Classify CLEAN
        res_clean = DNSQueryResult(
            server="8.8.8.8",
            protocol="udp",
            domain="www.google.com",
            qtype="A",
            success=True,
            latency_ms=42.0,
            answers=["142.250.1.1"],
        )
        c_clean = classify_pollution_result("www.google.com", "Google", "8.8.8.8", res_clean, ["142.250.1.1"], {"AS15169"}, {})
        self.assertEqual(c_clean.status, "CLEAN")

        # Classify POISONED via forged IP
        res_poison = DNSQueryResult(
            server="8.8.8.8",
            protocol="udp",
            domain="www.google.com",
            qtype="A",
            success=True,
            latency_ms=5.4,
            answers=["31.13.65.1"],
        )
        c_poison = classify_pollution_result("www.google.com", "Google", "8.8.8.8", res_poison, ["142.250.1.1"], {"AS15169"}, {})
        self.assertEqual(c_poison.status, "POISONED")

        # Classify POISONED via ASN deviation to CN IP
        intel_map = {"1.2.3.4": IPIntel(ip="1.2.3.4", asn="AS4134", is_cn=True)}
        res_cn_hijack = DNSQueryResult(
            server="114.114.114.114",
            protocol="udp",
            domain="www.google.com",
            qtype="A",
            success=True,
            latency_ms=12.0,
            answers=["1.2.3.4"],
        )
        c_hijack = classify_pollution_result("www.google.com", "114DNS", "114.114.114.114", res_cn_hijack, ["142.250.1.1"], {"AS15169"}, intel_map)
        self.assertEqual(c_hijack.status, "POISONED")

        # Classify TIMEOUT
        res_to = DNSQueryResult(
            server="8.8.8.8",
            protocol="udp",
            domain="www.google.com",
            qtype="A",
            success=False,
            latency_ms=2000.0,
            rcode="ERROR",
            error="timed out",
        )
        c_to = classify_pollution_result("www.google.com", "Google", "8.8.8.8", res_to, ["142.250.1.1"], {"AS15169"}, {})
        self.assertEqual(c_to.status, "TIMEOUT")

    def test_cjk_table_alignment(self):
        table = render_table(
            ["节点名称", "IP 地址", "状态"],
            [
                ["阿里 AliDNS", "223.5.5.5", "正常"],
                ["Cloudflare", "1.1.1.1", "正常 (Anycast)"],
            ],
        )
        lines = table.splitlines()
        widths = [display_width(strip_ansi(line)) for line in lines]
        self.assertEqual(len(widths), 6)
        self.assertEqual(len(set(widths)), 1, f"All table lines should have equal display width: {widths}")

    def test_ai_services_classification(self):
        # 1. Clean overseas US exit -> AVAILABLE
        avail, _ = classify_ai_probe(
            dns_status="FAKE_IP",
            tls_ok=True,
            exit_country_code="US",
            unsupported_ccs=SANCTIONED_PLUS_HK_CCS,
            explicit_region_block=False,
            cf_challenge=False,
        )
        self.assertEqual(avail, "AVAILABLE")

        # 2. HK / CN exit -> REGION_BLOCKED
        blk_hk, lbl_hk = classify_ai_probe(
            dns_status="FAKE_IP",
            tls_ok=True,
            exit_country_code="HK",
            unsupported_ccs=SANCTIONED_PLUS_HK_CCS,
            explicit_region_block=False,
            cf_challenge=False,
        )
        self.assertEqual(blk_hk, "REGION_BLOCKED")
        self.assertIn("HK", lbl_hk)

        blk_explicit, _ = classify_ai_probe(
            dns_status="CLEAN",
            tls_ok=True,
            exit_country_code="US",
            unsupported_ccs=set(),
            explicit_region_block=True,
            cf_challenge=False,
        )
        self.assertEqual(blk_explicit, "REGION_BLOCKED")

        # 3. Cloudflare challenge on 403 -> RISK_CHALLENGE
        chal, _ = classify_ai_probe(
            dns_status="FAKE_IP",
            tls_ok=True,
            exit_country_code="JP",
            unsupported_ccs=SANCTIONED_PLUS_HK_CCS,
            explicit_region_block=False,
            cf_challenge=True,
        )
        self.assertEqual(chal, "RISK_CHALLENGE")

        # 4. TLS failure or poisoned DNS -> UNREACHABLE
        unreach_tls, _ = classify_ai_probe(
            dns_status="CLEAN",
            tls_ok=False,
            exit_country_code="UNKNOWN",
            unsupported_ccs=SANCTIONED_PLUS_HK_CCS,
            explicit_region_block=False,
            cf_challenge=False,
        )
        self.assertEqual(unreach_tls, "UNREACHABLE")

        unreach_pol, _ = classify_ai_probe(
            dns_status="POISONED",
            tls_ok=True,
            exit_country_code="US",
            unsupported_ccs=SANCTIONED_PLUS_HK_CCS,
            explicit_region_block=False,
            cf_challenge=False,
        )
        self.assertEqual(unreach_pol, "UNREACHABLE")

    def test_web_server_endpoints(self):
        httpd = create_server(0)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            # 1. Static HTML
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                html = resp.read().decode("utf-8")
                self.assertIn("DNSGuard", html)

            # 2. API Status
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                status_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(status_data["status"], "ok")

            # 3. API Enrich offline IPs (198.18.0.1 and 127.0.0.1 resolve without network)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/enrich",
                data=json.dumps({"ips": ["198.18.0.1", "127.0.0.1"]}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                enrich_data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(enrich_data["results"]["198.18.0.1"]["is_fake_ip"])
                self.assertTrue(enrich_data["results"]["127.0.0.1"]["is_loopback"])
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
