from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .cloudflare import CloudflareError, api_token, classify, delete_record, list_records, zone_id
from .ct import fetch_ct_names
from .dns_checks import inspect_domain
from .policy import Policy, load_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dns-cloak",
        description=(
            "Shrink a domain's public DNS surface so subdomain finders "
            "have nothing to resolve. Does not brute-force names."
        ),
    )
    parser.add_argument("--version", action="version", version=f"dns-cloak {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    audit = sub.add_parser("audit", help="Show public leaks (CT + DNS hardening)")
    audit.add_argument("domain", nargs="?", help="Apex domain, e.g. example.com")
    audit.add_argument("--policy", help="Path to policy.yaml (supplies domain + allowlist)")
    audit.add_argument("--json", action="store_true", help="Machine-readable output")

    apply = sub.add_parser(
        "apply",
        help="Delete Cloudflare DNS records that are not on the public allowlist",
    )
    apply.add_argument("--policy", required=True, help="Path to policy.yaml")
    apply.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete records. Without this flag, only print the plan.",
    )

    args = parser.parse_args(argv)
    if args.cmd == "audit":
        return cmd_audit(args)
    if args.cmd == "apply":
        return cmd_apply(args)
    parser.error("unknown command")
    return 2


def _policy_or_domain(args) -> Policy:
    if args.policy:
        return load_policy(args.policy)
    if getattr(args, "domain", None):
        return Policy(domain=args.domain.lower(), public=("@", "www"))
    raise SystemExit("Pass a domain or --policy")


def cmd_audit(args) -> int:
    policy = _policy_or_domain(args)
    domain = policy.apex
    hardening = inspect_domain(domain)
    try:
        certs = fetch_ct_names(domain)
    except RuntimeError as exc:
        print(f"Certificate Transparency lookup failed: {exc}", file=sys.stderr)
        certs = []

    public = policy.public_fqdns()
    leaked = [c for c in certs if c.name not in public]
    cf_records = None
    hide = []
    try:
        token = api_token()
        zid = zone_id(token, domain)
        records = list_records(token, zid)
        _keep, hide = classify(policy, records)
        cf_records = records
    except CloudflareError:
        pass

    report = {
        "domain": domain,
        "public_allowlist": sorted(public),
        "nameservers": hardening.nameservers,
        "axfr_open": hardening.axfr_open,
        "nsec_enumerable": hardening.nsec_enumerable,
        "notes": hardening.notes,
        "certificate_transparency": {
            "unique_hostnames": [c.name for c in certs],
            "not_on_allowlist": [c.name for c in leaked],
        },
        "cloudflare_dns": None
        if cf_records is None
        else {
            "record_count": len(cf_records),
            "would_delete": [
                {"name": r.name, "type": r.type, "content": r.content} for r in hide
            ],
        },
        "limits": [
            "Names already in Certificate Transparency stay there. Deleting DNS does not erase CT.",
            "A public A/AAAA/CNAME is always enumerable by anyone who guesses or is told the name.",
            "Cloudflare orange-cloud hides the origin IP, not the hostname.",
            "Private apps need no public DNS: Cloudflare Tunnel + WARP / private hostname.",
        ],
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"dns-cloak audit  {domain}")
    print(f"allowlist        {', '.join(sorted(public)) or '(empty)'}")
    print(f"nameservers      {', '.join(hardening.nameservers) or '(none)'}")
    print(f"AXFR open        {', '.join(hardening.axfr_open) or 'no'}")
    print(f"NSEC walkable    {'yes' if hardening.nsec_enumerable else 'no'}")
    print()
    print(f"CT hostnames ({len(certs)}) — already issued by a public CA:")
    if not certs:
        print("  (none, or crt.sh failed)")
    for cert in certs:
        flag = " PUBLIC" if cert.name in public else " LEAK"
        print(f"  {flag:8} {cert.name}")
    if cf_records is None:
        print()
        print("Cloudflare DNS skipped (set CLOUDFLARE_API_TOKEN to classify live records).")
    else:
        print()
        print(f"Cloudflare records not on allowlist ({len(hide)}):")
        if not hide:
            print("  none")
        for rec in hide:
            print(f"  {rec.type:6} {rec.name}  -> {rec.content}")
    print()
    print("Limits:")
    for line in report["limits"]:
        print(f"  - {line}")
    for note in hardening.notes:
        print(f"  - {note}")
    return 0


def cmd_apply(args) -> int:
    policy = load_policy(args.policy)
    try:
        token = api_token()
        zid = zone_id(token, policy.apex)
        records = list_records(token, zid)
    except CloudflareError as exc:
        print(exc, file=sys.stderr)
        return 1
    keep, hide = classify(policy, records)
    print(f"zone {policy.apex}  keep={len(keep)}  hide={len(hide)}")
    for rec in hide:
        print(f"  DELETE {rec.type:6} {rec.name}  ({rec.content})")
    if not hide:
        print("Nothing to delete.")
        return 0
    if not args.yes:
        print("Dry run. Re-run with --yes to delete these records.")
        return 0
    for rec in hide:
        delete_record(token, zid, rec.id)
        print(f"  deleted {rec.id} {rec.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
