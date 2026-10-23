from __future__ import annotations

from dataclasses import dataclass
import socket
import subprocess


@dataclass
class DnsHardening:
    nameservers: list[str]
    axfr_open: list[str]
    nsec_enumerable: bool
    notes: list[str]


def _dig(*args: str) -> str:
    try:
        proc = subprocess.run(
            ["dig", "+time=3", "+tries=1", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def nameservers(domain: str) -> list[str]:
    out = _dig("NS", domain, "+short")
    hosts = [line.strip().rstrip(".") for line in out.splitlines() if line.strip()]
    return sorted(set(hosts))


def axfr_open_on(domain: str, ns_hosts: list[str]) -> list[str]:
    open_ns: list[str] = []
    for ns in ns_hosts:
        out = _dig("AXFR", domain, f"@{ns}")
        lower = out.lower()
        if "transfer failed" in lower or "refused" in lower or "not implemented" in lower:
            continue
        answers = [
            line
            for line in out.splitlines()
            if line and not line.startswith(";") and "IN" in line
        ]
        if len(answers) >= 3:
            open_ns.append(ns)
    return open_ns


def nsec_walkable(domain: str) -> bool:
    out = _dig(f"does-not-exist-cloak-probe.{domain}", "A", "+dnssec", "+noall", "+authority")
    return " NSEC " in out and " NSEC3 " not in out


def resolve_exists(name: str) -> bool:
    try:
        socket.getaddrinfo(name, None)
        return True
    except socket.gaierror:
        return False


def inspect_domain(domain: str) -> DnsHardening:
    notes: list[str] = []
    ns = nameservers(domain)
    if not ns:
        notes.append("dig NS returned no nameservers (is dig installed / is the domain delegated?)")
    axfr = axfr_open_on(domain, ns) if ns else []
    nsec = nsec_walkable(domain) if ns else False
    if nsec:
        notes.append(
            "NSEC is present. Some enumerators can walk the zone and list every public name."
        )
    if axfr:
        notes.append("AXFR is open on at least one nameserver. Close zone transfers.")
    return DnsHardening(
        nameservers=ns, axfr_open=axfr, nsec_enumerable=nsec, notes=notes
    )
