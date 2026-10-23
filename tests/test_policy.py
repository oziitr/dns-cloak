import unittest
from pathlib import Path
import tempfile

from dns_cloak.policy import Policy, load_policy
from dns_cloak.cloudflare import DnsRecord, classify
from dns_cloak.ct import parse_ct_rows


class PolicyTests(unittest.TestCase):
    def test_apex_and_www(self):
        policy = Policy(domain="Example.COM.", public=("@", "www"))
        self.assertEqual(policy.public_fqdns(), {"example.com", "www.example.com"})
        self.assertTrue(policy.is_public_name("example.com"))
        self.assertTrue(policy.is_public_name("WWW.example.com."))
        self.assertFalse(policy.is_public_name("panel.example.com"))
        self.assertFalse(policy.is_public_name("db.internal.example.com"))

    def test_load_example_policy(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"
        policy = load_policy(path)
        self.assertEqual(policy.apex, "example.com")
        self.assertIn("www.example.com", policy.public_fqdns())

    def test_classify_hides_panel(self):
        policy = Policy(domain="example.com", public=("@", "www"))
        records = [
            DnsRecord("1", "example.com", "A", "1.2.3.4", True),
            DnsRecord("2", "www.example.com", "CNAME", "example.com", True),
            DnsRecord("3", "example.com", "NS", "ns1.cloudflare.com", None),
            DnsRecord("4", "panel.example.com", "A", "1.2.3.4", True),
        ]
        keep, hide = classify(policy, records)
        self.assertEqual({r.name for r in hide}, {"panel.example.com"})
        self.assertIn("example.com", {r.name for r in keep})

    def test_ct_parser_skips_wildcards_and_other_domains(self):
        rows = [
            {
                "name_value": "*.example.com\npanel.example.com",
                "common_name": "example.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2026-01-01",
                "not_after": "2026-04-01",
            },
            {
                "name_value": "other.org",
                "common_name": "other.org",
                "issuer_name": "X",
                "not_before": "",
                "not_after": "",
            },
        ]
        names = {c.name for c in parse_ct_rows(rows, "example.com")}
        self.assertEqual(names, {"example.com", "panel.example.com"})
        self.assertNotIn("*.example.com", names)


class YamlSubsetTests(unittest.TestCase):
    def test_lists_and_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write(
                "domain: demo.test\n"
                "public:\n"
                "  - '@'\n"
                "  - www  # site\n"
                "keep_types:\n"
                "  - NS\n"
                "keep_names: []\n"
            )
            handle.flush()
            policy = load_policy(handle.name)
        self.assertEqual(policy.domain, "demo.test")
        self.assertEqual(set(policy.public), {"@", "www"})


if __name__ == "__main__":
    unittest.main()
