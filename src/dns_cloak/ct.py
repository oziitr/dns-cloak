from __future__ import annotations

from dataclasses import dataclass
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


CRT_SH = "https://crt.sh/"
USER_AGENT = "dns-cloak/0.1 (+https://github.com/oziitr/dns-cloak)"


@dataclass(frozen=True)
class CertName:
    name: str
    issuer: str
    not_before: str
    not_after: str


def fetch_ct_names(domain: str, timeout: float = 30.0) -> list[CertName]:
    """Read Certificate Transparency via crt.sh for names already issued.

    This does not brute-force DNS. It only lists hostnames that a public CA
    already published. Historical rows stay in CT even after you delete DNS.
    """
    query = f"%.{domain}"
    url = CRT_SH + "?" + urllib.parse.urlencode({"q": query, "output": "json"})
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"crt.sh HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"crt.sh unreachable: {exc.reason}") from exc

    if not raw.strip():
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("crt.sh returned non-JSON (rate limited or HTML error page)") from exc
    if not isinstance(rows, list):
        return []
    return parse_ct_rows(rows, domain)


def parse_ct_rows(rows: list[dict], domain: str) -> list[CertName]:
    apex = domain.lower().rstrip(".")
    seen: dict[str, CertName] = {}
    for row in rows:
        issuer = str(row.get("issuer_name") or "")
        not_before = str(row.get("not_before") or "")
        not_after = str(row.get("not_after") or "")
        blob = "\n".join(
            part
            for part in (
                str(row.get("name_value") or ""),
                str(row.get("common_name") or ""),
            )
            if part
        )
        for raw in blob.replace(",", "\n").splitlines():
            name = raw.strip().lower().rstrip(".")
            if name.startswith("*."):
                continue
            if name != apex and not name.endswith("." + apex):
                continue
            if name not in seen:
                seen[name] = CertName(
                    name=name,
                    issuer=issuer,
                    not_before=not_before,
                    not_after=not_after,
                )
    return sorted(seen.values(), key=lambda item: item.name)
