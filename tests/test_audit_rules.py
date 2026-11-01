import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "skills/proxy-ruleset-organizer/scripts/audit_rules.py"
spec = importlib.util.spec_from_file_location("audit_rules", SCRIPT)
audit_rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_rules)


class AuditRulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("RULESET_TEST_TMPDIR"))
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def dataset(self, name, text):
        p = self.root / name
        p.mkdir()
        (p / "Example.list").write_text(text, encoding="utf-8")
        return audit_rules.read_rules(p)

    def test_suffix_boundary_and_cross_file(self):
        p = self.root / "rules"
        p.mkdir()
        (p / "A.list").write_text("DOMAIN-SUFFIX,example.com\nDOMAIN,notexample.com\nDOMAIN,example.com.other.net\n")
        (p / "B.list").write_text("DOMAIN,a.example.com\nDOMAIN-SUFFIX,b.a.example.com\n")
        r = audit_rules.audit(audit_rules.read_rules(p))
        overlaps = [f for f in r["findings"] if f["kind"] == "domain_suffix_overlap"]
        self.assertEqual(len(overlaps), 2)
        self.assertTrue(all(f["detail"].startswith("cross file") for f in overlaps))

    def test_duplicate_is_not_just_suffix_overlap(self):
        rules = self.dataset("dup", "DOMAIN,example.com\nDOMAIN,example.com\n")
        r = audit_rules.audit(rules)
        self.assertEqual([f["kind"] for f in r["findings"]], ["exact_rule_duplicate"])

    def test_ip_overlap_ipv4_and_ipv6(self):
        rules = self.dataset("ip", "IP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR,192.0.2.1/32,no-resolve\nIP-CIDR6,2001:db8::/32\nIP-CIDR6,2001:db8::1/128\n")
        r = audit_rules.audit(rules)
        self.assertEqual(len([f for f in r["findings"] if f["kind"] == "ip_network_overlap"]), 2)

    def test_length_before_alphabet(self):
        values = ["bb.example", "z.example", "aa.example"]
        self.assertEqual(sorted(values, key=audit_rules.value_sort_key), ["z.example", "aa.example", "bb.example"])

    def test_pure_reorder_and_parameter_change(self):
        before = self.dataset("before", "DOMAIN-SUFFIX,example.com\nIP-CIDR,192.0.2.1/32,no-resolve\n")
        after = self.dataset("after", "IP-CIDR,192.0.2.1/32,no-resolve\nDOMAIN-SUFFIX,example.com\n")
        self.assertTrue(audit_rules.compare(before, after)["pass"])
        changed = self.dataset("changed", "DOMAIN-SUFFIX,example.com\nIP-CIDR,192.0.2.1/32\n")
        self.assertFalse(audit_rules.compare(before, changed)["pass"])

    def test_resolving_ip_or_complex_rule_cannot_be_blindly_reordered(self):
        for n, rule in enumerate(["IP-CIDR,192.0.2.1/32", "AND,((DOMAIN,example.com),(DST-PORT,443))"]):
            a = self.dataset("a" + str(n), rule + "\nDOMAIN,other.example\n")
            b = self.dataset("b" + str(n), "DOMAIN,other.example\n" + rule + "\n")
            r = audit_rules.compare(a, b)
            self.assertFalse(r["pass"])
            self.assertTrue(r["manual_review"])

    def test_templates_stay_disabled(self):
        a = self.dataset("a", "# DOMAIN,example.com\nDOMAIN,other.example\n")
        b = self.dataset("b", "DOMAIN,example.com\nDOMAIN,other.example\n")
        self.assertFalse(audit_rules.compare(a, b)["pass"])
        self.assertTrue(any(e["kind"] == "disabled_templates_changed" for e in audit_rules.compare(a, b)["errors"]))

    def test_explicit_delta_and_stale_approval(self):
        a = self.dataset("a", "DOMAIN,old.example\n")
        b = self.dataset("b", "DOMAIN,new.example\n")
        approval = {"Example.list": {"remove": ["DOMAIN,old.example"], "add": ["DOMAIN,new.example"]}}
        self.assertFalse(audit_rules.compare(a, b)["pass"])
        self.assertTrue(audit_rules.compare(a, b, approval)["pass"])
        self.assertFalse(audit_rules.compare(a, a, approval)["pass"])

    def test_tld_is_optional_and_internal_name_is_not_auto_invalidated(self):
        data = self.dataset("tld", "DOMAIN,host.internal\n")
        self.assertFalse(audit_rules.audit(data)["tld_checked"])
        r = audit_rules.audit(data, {"COM", "NET"})
        self.assertEqual(r["findings"][0]["kind"], "tld_not_in_supplied_public_list")

    def test_findings_limit_is_explicit(self):
        data = self.dataset("cap", "DOMAIN,one.internal\nDOMAIN,two.internal\n")
        r = audit_rules.audit(data, {"COM"}, 1)
        self.assertEqual(len(r["findings"]), 1)
        self.assertTrue(r["findings_truncated"])


if __name__ == "__main__":
    unittest.main()
