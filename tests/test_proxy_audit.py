import unittest

from dnscheck.detectors.dns_leak import TransparentHijackProbe, evaluate_oast_vectors
from dnscheck.detectors.proxy_audit import (
    audit_surge_conf_text,
    parse_surge_rule_explain,
    parse_surge_status_output,
)
from dnscheck.enricher.ip_intel import IPIntel
from dnscheck.protocol.interactsh import InteractshInteraction


class TestProxyAuditAndRefinements(unittest.TestCase):
    def test_parse_surge_status(self):
        sample = """
Surge 6.9.1 (12290)
Profile: TAG
Profile Path: /tmp/TAG.conf
Mode: rule
Features:
  enhanced-mode: On
  system-proxy: Off
"""
        parsed = parse_surge_status_output(sample)
        self.assertEqual(parsed["version"], "Surge 6.9.1 (12290)")
        self.assertEqual(parsed["profile"], "TAG")
        self.assertTrue(parsed["enhanced_mode"])
        self.assertFalse(parsed["system_proxy"])

    def test_parse_surge_rule_explain_leak_vs_clean(self):
        leaky_out = """
Matched rule: FINAL,Proxy,dns-failed
Final policy: US-Node (Shadowsocks)
Duration: 618.89 ms
Notes:
  Rule evaluating requires DNS lookup for rule: RULE-SET LAN
  DNS lookup for probe.oast.me completed in 613.4ms. A record count: 1, AAAA record count: 0
"""
        r_leak = parse_surge_rule_explain("probe.oast.me", leaky_out)
        self.assertTrue(r_leak.triggered_local_dns)
        self.assertEqual(r_leak.trigger_rule, "RULE-SET LAN")
        self.assertAlmostEqual(r_leak.dns_lookup_ms, 613.4)
        self.assertAlmostEqual(r_leak.duration_ms, 618.89)

        clean_out = """
Matched rule: FINAL,Proxy,dns-failed
Final policy: US-Node (Shadowsocks)
Duration: 4.12 ms
Notes:
  Rule matched: FINAL
"""
        r_clean = parse_surge_rule_explain("probe.oast.me", clean_out)
        self.assertFalse(r_clean.triggered_local_dns)
        self.assertIsNone(r_clean.trigger_rule)
        self.assertAlmostEqual(r_clean.duration_ms, 4.12)

    def test_audit_surge_conf_detects_issues_and_ignores_proxy_secrets(self):
        leaky_conf = """
[General]
ipv6 = true
hijack-dns = *:53

[Proxy]
#!include https://secret-provider.example/sub?token=SUPER_SECRET_TOKEN_12345

[Rule]
PROCESS-NAME,/Applications/iTerm.app/,DIRECT
RULE-SET,LAN,DIRECT
RULE-SET,https://example.com/rules/OpenAi.list,Proxy
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
"""
        res = audit_surge_conf_text(leaky_conf)
        self.assertTrue(res["uses_plaintext_system_dns"])
        self.assertFalse(res["encrypted_dns_configured"])
        self.assertTrue(res["ipv6_enabled"])
        self.assertTrue(res["hijack_dns_all"])
        self.assertTrue(res["lan_before_proxy_rules"])
        self.assertTrue(res["terminal_direct_above_dev_rules"])
        self.assertEqual(len(res["missing_no_resolve"]), 3)
        # Ensure proxy subscription token is never retained anywhere in audit output
        self.assertNotIn("SUPER_SECRET_TOKEN_12345", str(res))

        clean_conf = """
[General]
ipv6 = false
dns-server = 223.5.5.5, 119.29.29.29
encrypted-dns-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query

[Rule]
PROCESS-NAME,gh,HK03
DOMAIN-SUFFIX,github.com,HK03
PROCESS-NAME,/Applications/iTerm.app/,DIRECT
RULE-SET,LAN,DIRECT,no-resolve
RULE-SET,https://example.com/rules/OpenAi.list,Proxy,no-resolve
RULE-SET,https://example.com/rules/ChinaDomain.list,DIRECT,no-resolve
DOMAIN-SUFFIX,cn,DIRECT
GEOIP,CN,DIRECT,no-resolve
FINAL,Proxy,dns-failed
"""
        res_clean = audit_surge_conf_text(clean_conf)
        self.assertFalse(res_clean["uses_plaintext_system_dns"])
        self.assertTrue(res_clean["encrypted_dns_configured"])
        self.assertFalse(res_clean["ipv6_enabled"])
        self.assertFalse(res_clean["hijack_dns_all"])
        self.assertFalse(res_clean["lan_before_proxy_rules"])
        self.assertFalse(res_clean["terminal_direct_above_dev_rules"])
        self.assertEqual(len(res_clean["missing_no_resolve"]), 0)
        self.assertTrue(res_clean["has_china_domain_rule"])

    def test_surge_txt_only_nuance_and_proxy_hijack_field(self):
        intel_map = {
            "219.144.80.148": IPIntel(ip="219.144.80.148", asn="AS134768", is_cn=True),
            "172.253.1.20": IPIntel(ip="172.253.1.20", asn="AS15169", is_cn=False),
        }
        meta = {
            "sys-v4": ("a.oast.me", ["198.18.5.10"], True, 1.0),
            "sys-v6": ("b.oast.me", [], False, 1.0),
            "qtype65": ("c.oast.me", [], False, 10.0),
            "udp-sys": ("d.oast.me", [], False, 35.0),
            "direct-sni": ("e.oast.me", ["198.18.5.11"], True, 90.0),
            "proxy-sni": ("f.oast.me", [], False, 110.0),
        }
        interactions = [
            InteractshInteraction("dns", "u", "d", "udp-sys", "TXT", "219.144.80.148"),
            InteractshInteraction("dns", "u", "e", "direct-sni", "A", "172.253.1.20"),
            InteractshInteraction("dns", "u", "f", "proxy-sni", "A", "172.253.1.20"),
        ]
        probes, race, q65, bypass = evaluate_oast_vectors(meta, interactions, intel_map, proxy_active=True)
        by_id = {p.vector_id: p for p in probes}
        self.assertFalse(race)
        self.assertFalse(q65)
        self.assertFalse(bypass)
        self.assertEqual(by_id["udp-sys"].status, "INFO")
        self.assertEqual(by_id["direct-sni"].status, "SAFE")
        self.assertEqual(by_id["proxy-sni"].status, "SAFE")

        hp = TransparentHijackProbe(
            target_server="8.8.8.8:53",
            target_name="Google Public DNS",
            probe_domain="o-o.myaddr.l.google.com",
            success=True,
            hijacked=False,
            proxy_hijacked=True,
        )
        self.assertTrue(hp.to_dict()["proxy_hijacked"])


if __name__ == "__main__":
    unittest.main()
