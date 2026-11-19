import unittest

from dnscheck.detectors.claude_guard import (
    CLAUDE_CHAIN_TARGETS,
    ClaudeTargetCheck,
    evaluate_claude_consistency,
    generate_claude_rules,
)


class TestClaudeGuard(unittest.TestCase):
    def test_claude_target_inventory_and_rule_export(self):
        # Verify exact 14 domains + 1 IP CIDR (34.8.0.0/16) = 15 targets
        self.assertEqual(len(CLAUDE_CHAIN_TARGETS), 15)
        targets = {t["target"] for t in CLAUDE_CHAIN_TARGETS}
        expected = {
            "claude.ai",
            "anthropic.com",
            "claude.com",
            "claudeusercontent.com",
            "claude.app",
            "claudemcpcontent.com",
            "clau.de",
            "api-iam.intercom.io",
            "nexus-websocket-a.intercom.io",
            "us5.datadoghq.com",
            "r.stripe.com",
            "us.sentry.io",
            "siftscience.com",
            "fcmtoken.googleapis.com",
            "34.8.0.0/16",
        }
        self.assertEqual(targets, expected)

        surge_rules = generate_claude_rules("surge", policy="🧲 Claude")
        self.assertIn('DOMAIN-SUFFIX,claude.ai,"🧲 Claude"', surge_rules)
        self.assertIn('DOMAIN-SUFFIX,siftscience.com,"🧲 Claude"', surge_rules)
        self.assertIn('IP-CIDR,34.8.0.0/16,"🧲 Claude",no-resolve', surge_rules)

        clash_rules = generate_claude_rules("clash", policy="Claude")
        self.assertIn("  - DOMAIN,r.stripe.com,Claude", clash_rules)
        self.assertIn("  - IP-CIDR,34.8.0.0/16,Claude,no-resolve", clash_rules)

    def test_whitebox_consistency_detects_direct_leak_and_drift(self):
        checks = [
            ClaudeTargetCheck("claude.ai", "DOMAIN-SUFFIX", "核心主站", "CRITICAL", final_policy="US-Res-05 (Shadowsocks)", cf_exit_cc="US"),
            ClaudeTargetCheck("anthropic.com", "DOMAIN-SUFFIX", "API", "CRITICAL", final_policy="US-Res-05 (Shadowsocks)", cf_exit_cc="US"),
            ClaudeTargetCheck("siftscience.com", "DOMAIN-SUFFIX", "反欺诈", "CRITICAL", matched_rule="GEOIP,CN,DIRECT", final_policy="DIRECT (DIRECT)"),
            ClaudeTargetCheck("fcmtoken.googleapis.com", "DOMAIN", "FCM", "MEDIUM", matched_rule="Google.list", final_policy="SG-01 (Shadowsocks)"),
            ClaudeTargetCheck("34.8.0.0/16", "IP-CIDR", "GCP", "HIGH", final_policy="US-Res-05 (Shadowsocks)"),
        ]
        rep = evaluate_claude_consistency(checks, whitebox_client="Surge 6.9.1")
        self.assertEqual(rep.baseline_policy, "US-Res-05")
        self.assertEqual(rep.consistent_count, 3)
        self.assertEqual(rep.direct_leak_count, 1)
        self.assertEqual(rep.split_drift_count, 1)
        self.assertEqual(rep.verdict, "RISK")
        self.assertLess(rep.score, 80)

    def test_blackbox_consistency_all_clean(self):
        checks = [
            ClaudeTargetCheck("claude.ai", "DOMAIN-SUFFIX", "核心主站", "CRITICAL", dns_status="FAKE_IP", cf_exit_ip="203.0.113.5", cf_exit_cc="US"),
            ClaudeTargetCheck("siftscience.com", "DOMAIN-SUFFIX", "反欺诈", "CRITICAL", dns_status="FAKE_IP", cf_exit_ip="203.0.113.5", cf_exit_cc="US"),
            ClaudeTargetCheck("r.stripe.com", "DOMAIN", "支付", "CRITICAL", dns_status="FAKE_IP"),
        ]
        rep = evaluate_claude_consistency(checks, whitebox_client=None)
        self.assertEqual(rep.verdict, "SAFE")
        self.assertEqual(rep.score, 100)
        self.assertEqual(rep.consistent_count, 3)


if __name__ == "__main__":
    unittest.main()
