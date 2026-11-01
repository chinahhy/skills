#!/usr/bin/env python3
"""Read-only audit/comparison of hand-maintained classical text rules; Python 3.9+."""
import argparse
from collections import Counter, defaultdict
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

SIMPLE = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
TEMPLATE = re.compile(r"^(?:#|//)\s*[A-Z][A-Z0-9-]*\s*,")


def value_sort_key(value, kind="", original_line=0):
    return len(value), value.lower(), kind, original_line


def ref(row):
    return {k: row[k] for k in ("file", "line", "rule")}


def read_rules(root, pattern="*.list"):
    root = Path(root)
    if not root.exists():
        raise ValueError("Input does not exist: " + str(root))
    paths = [root] if root.is_file() else sorted(root.rglob(pattern))
    if not paths:
        raise ValueError("No input files matched")
    files = {}
    for path in paths:
        if path.is_symlink():
            raise ValueError("Review symlink input explicitly: " + str(path))
        name = path.name if root.is_file() else path.relative_to(root).as_posix()
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
        rows, templates = [], []
        for number, source in enumerate(text.splitlines(), 1):
            rule = source.strip()
            if not rule:
                continue
            if rule.startswith(("#", "//")):
                if TEMPLATE.match(rule):
                    templates.append(rule)
                continue
            kind, _, rest = rule.partition(",")
            row = {"file": name, "line": number, "rule": rule,
                   "kind": kind, "simple": kind in SIMPLE, "issues": []}
            if kind not in SIMPLE:
                row["issues"].append("not_parsed_by_helper")
            else:
                parts = rule.split(",")
                value = parts[1].strip() if len(parts) > 1 else ""
                options = [p.strip() for p in parts[2:]]
                row.update(value=value, options=options)
                if not value:
                    row["issues"].append("empty_value")
                if options and (not kind.startswith("IP-") or options != ["no-resolve"]):
                    row["issues"].append("modifier_requires_consumer_review")
                if kind.startswith("DOMAIN"):
                    if value and (len(value) > 253 or not all(
                        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                        for label in value.split("."))):
                        row["issues"].append("domain_shape_review_not_engine_error")
                else:
                    try:
                        if "/" not in value:
                            raise ValueError("CIDR prefix required")
                        net = ipaddress.ip_network(value, strict=False)
                        row.update(ip_version=net.version, network=str(net))
                        if value != str(net):
                            row["issues"].append("noncanonical_cidr_preserved")
                        if kind == "IP-CIDR6" and net.version == 4:
                            row["issues"].append("ipv4_with_cidr6_alias_check_consumers")
                    except ValueError:
                        row["issues"].append("invalid_cidr")
            rows.append(row)
        files[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "rules": rows,
                       "disabled_templates": templates}
    return files


def order_sensitive(rows):
    if any(not r["simple"] or r["issues"] for r in rows):
        return True
    domains = any(r["kind"].startswith("DOMAIN") for r in rows)
    resolving_ip = any(r["kind"].startswith("IP-") and "no-resolve" not in r.get("options", []) for r in rows)
    return domains and resolving_ip


def audit(files, tlds=None, max_findings=500):
    findings, truncated = [], False

    def emit(kind, refs, detail=""):
        nonlocal truncated
        if len(findings) >= max_findings:
            truncated = True
        else:
            findings.append({"kind": kind, "rules": refs, "detail": detail})

    rows = [r for f in files.values() for r in f["rules"]]
    exact, suffixes = defaultdict(list), defaultdict(list)
    networks = defaultdict(list)
    for row in rows:
        exact[row["rule"]].append(row)
        for issue in row["issues"]:
            emit(issue, [ref(row)])
        if row["simple"] and row["kind"].startswith("DOMAIN") and row.get("value"):
            value = row["value"].lower()
            if tlds is not None and value.rsplit(".", 1)[-1].upper() not in tlds:
                emit("tld_not_in_supplied_public_list", [ref(row)], "May be an intentional internal name; do not auto-delete")
            if row["kind"] == "DOMAIN-SUFFIX":
                suffixes[value].append(row)
        if "network" in row:
            net = ipaddress.ip_network(row["network"])
            networks[net.version].append((int(net.network_address), int(net.broadcast_address), row))
    for group in exact.values():
        if len(group) > 1:
            emit("exact_rule_duplicate", [ref(r) for r in group])
    seen = set()
    for child in rows:
        if not child["simple"] or not child["kind"].startswith("DOMAIN") or not child.get("value"):
            continue
        labels = child["value"].lower().split(".")
        for i in range(len(labels)):
            for parent in suffixes.get(".".join(labels[i:]), []):
                if parent is child:
                    continue
                pair = tuple(sorted(((parent["file"], parent["line"]), (child["file"], child["line"]))))
                if pair in seen:
                    continue
                seen.add(pair)
                emit("domain_suffix_overlap", [ref(parent), ref(child)],
                     "same file" if parent["file"] == child["file"] else "cross file: inspect outer policy order")
    for version, nets in networks.items():
        nets.sort(key=lambda n: (n[0], n[1], n[2]["file"], n[2]["line"]))
        stop = False
        for i, (low, high, a) in enumerate(nets):
            for j in range(i + 1, len(nets)):
                low2, high2, b = nets[j]
                if low2 > high:
                    break
                emit("ip_network_overlap", [ref(a), ref(b)], "IPv" + str(version))
                if truncated:
                    stop = True
                    break
            if stop:
                break
    return {"file_count": len(files), "rule_count": len(rows), "tld_checked": tlds is not None,
            "files": files, "findings": findings, "findings_truncated": truncated}


def compare(before, after, approved=None):
    approved = approved or {}
    if not isinstance(approved, dict):
        raise ValueError("Approved changes must be an object keyed by relative file path")
    errors, manual = [], []
    if set(before) != set(after):
        errors.append({"kind": "file_set_changed", "before": sorted(before), "after": sorted(after)})
    extra = set(approved) - (set(before) & set(after))
    if extra:
        errors.append({"kind": "unused_approval_files", "files": sorted(extra)})
    for path in sorted(set(before) & set(after)):
        old_rows, new_rows = before[path]["rules"], after[path]["rules"]
        old = Counter(r["rule"] for r in old_rows)
        new = Counter(r["rule"] for r in new_rows)
        change = approved.get(path, {})
        if not isinstance(change, dict) or set(change) - {"remove", "add"}:
            raise ValueError("Invalid approval for " + path)
        for key in ("remove", "add"):
            if not isinstance(change.get(key, []), list) or not all(isinstance(x, str) for x in change.get(key, [])):
                raise ValueError("Approval values must be lists of full rule strings: " + path)
        remove, add = Counter(change.get("remove", [])), Counter(change.get("add", []))
        if remove & add or remove - (old - new) or add - (new - old):
            errors.append({"kind": "unused_or_unmatched_approval", "file": path})
        expected = old - remove
        expected.update(add)
        if expected != new:
            errors.append({"kind": "unapproved_rule_delta", "file": path,
                           "missing": list((expected - new).elements()), "added": list((new - expected).elements())})
        if Counter(before[path]["disabled_templates"]) != Counter(after[path]["disabled_templates"]):
            errors.append({"kind": "disabled_templates_changed", "file": path})
        sequence_changed = [r["rule"] for r in old_rows] != [r["rule"] for r in new_rows]
        if sequence_changed and (order_sensitive(old_rows) or order_sensitive(new_rows)):
            manual.append({"file": path, "reason": "Complex, unparsed or DNS-sensitive rules changed sequence; use the target engine"})
    return {"pass": not errors and not manual, "errors": errors, "manual_review": manual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--pattern", default="*.list")
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--approved-changes", type=Path)
    parser.add_argument("--tlds", type=Path)
    parser.add_argument("--max-findings", type=int, default=500)
    args = parser.parse_args()
    try:
        if args.max_findings < 1:
            raise ValueError("max-findings must be positive")
        if args.approved_changes and not args.compare:
            raise ValueError("approved-changes requires --compare")
        tlds = None
        if args.tlds:
            tlds = {l.strip().upper() for l in args.tlds.read_text(encoding="utf-8-sig").splitlines()
                    if l.strip() and not l.lstrip().startswith("#")}
            if not tlds:
                raise ValueError("Supplied TLD list is empty")
        files = read_rules(args.root, args.pattern)
        report = audit(files, tlds, args.max_findings)
        code = 0
        if args.compare:
            after = read_rules(args.compare, args.pattern)
            approvals = json.loads(args.approved_changes.read_text(encoding="utf-8-sig")) if args.approved_changes else {}
            report["comparison"] = compare(files, after, approvals)
            code = 0 if report["comparison"]["pass"] else 2
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return code
    except (OSError, UnicodeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
