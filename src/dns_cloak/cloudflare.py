from __future__ import annotations

from dataclasses import dataclass
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .policy import Policy

API = "https://api.cloudflare.com/client/v4"
USER_AGENT = "dns-cloak/0.1"


@dataclass(frozen=True)
class DnsRecord:
    id: str
    name: str
    type: str
    content: str
    proxied: bool | None


class CloudflareError(RuntimeError):
    pass


def api_token() -> str:
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        raise CloudflareError(
            "CLOUDFLARE_API_TOKEN is empty. Audit still works; apply needs Zone:DNS:Edit."
        )
    return token


def _request(token: str, method: str, path: str, query: dict | None = None) -> dict:
    url = API + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=context) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise CloudflareError(f"Cloudflare HTTP {exc.code}: {body[:500]}") from exc
    if not payload.get("success"):
        raise CloudflareError(f"Cloudflare error: {payload.get('errors')}")
    return payload


def zone_id(token: str, domain: str) -> str:
    payload = _request(token, "GET", "/zones", {"name": domain, "per_page": "1"})
    result = payload.get("result") or []
    if not result:
        raise CloudflareError(f"No Cloudflare zone named {domain}")
    return str(result[0]["id"])


def list_records(token: str, zid: str) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    page = 1
    while True:
        payload = _request(
            token,
            "GET",
            f"/zones/{zid}/dns_records",
            {"per_page": "100", "page": str(page)},
        )
        for row in payload.get("result") or []:
            records.append(
                DnsRecord(
                    id=str(row["id"]),
                    name=str(row["name"]).lower().rstrip("."),
                    type=str(row["type"]).upper(),
                    content=str(row.get("content") or ""),
                    proxied=row.get("proxied"),
                )
            )
        info = payload.get("result_info") or {}
        total_pages = int(info.get("total_pages") or 1)
        if page >= total_pages:
            break
        page += 1
    return records


def delete_record(token: str, zid: str, record_id: str) -> None:
    _request(token, "DELETE", f"/zones/{zid}/dns_records/{record_id}")


def classify(policy: Policy, records: list[DnsRecord]) -> tuple[list[DnsRecord], list[DnsRecord]]:
    keep: list[DnsRecord] = []
    hide: list[DnsRecord] = []
    for rec in records:
        if rec.type in policy.keep_types:
            keep.append(rec)
            continue
        if policy.is_public_name(rec.name):
            keep.append(rec)
        else:
            hide.append(rec)
    return keep, hide
