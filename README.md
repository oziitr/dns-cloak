# dns-cloak

A domain’s **public** subdomains cannot be made invisible. If a name has a public DNS record or a public TLS certificate, finder tools can learn it. This project shrinks that public surface to an allowlist and moves everything else off DNS.

[**View the source**](https://github.com/oziitr/dns-cloak)

## What is actually possible

Subdomain finders do not magically list “hidden” records. They combine:

1. **Public DNS** — any `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `SRV` that answers
2. **Certificate Transparency** — every hostname a public CA (Let’s Encrypt, Google, Cloudflare Universal SSL, …) put in a cert
3. **Zone walking** — `AXFR` if you left transfers open, or `NSEC` on some DNSSEC setups
4. **Old copies** — search indexes, passive DNS, chat logs, JavaScript, emails

Cloudflare’s orange cloud hides the **origin IP**. It does **not** hide the hostname. A proxied `panel.example.com` still appears in DNS and usually in CT.

| Goal | What works |
| --- | --- |
| Public site only | Apex + `www` in DNS. Delete the rest. |
| Admin / DB / staging | No public name. Cloudflare Tunnel + WARP (private IP or private hostname). |
| TLS without leaking extra names | Wildcard `*.example.com` for the public zone, or a **private CA / Origin CA** for names that never enter public DNS. |
| Names already in crt.sh | You cannot erase history. You can stop issuing new unique certs and stop resolving the names. |

Wildcard DNS (`*.example.com → same IP`) does **not** hide real hosts. It only makes dictionary brute-force noisy. CT and previous records still leak the real labels.

## What this repo does

- `dns-cloak audit` — Certificate Transparency (crt.sh), nameserver list, AXFR closed?, NSEC walkable?, optional Cloudflare record classify
- `dns-cloak apply` — delete Cloudflare DNS records that are **not** on your public allowlist (`--yes` required)
- `examples/policy.yaml` — the allowlist
- `examples/cloudflared-private.yml` — tunnel config **without** public `hostname:` ingress (so Cloudflare does not create a public DNS name)

It does **not** brute-force other people’s zones and it does **not** un-publish CT history.

## Run locally

Python 3.10+ and `dig` (for AXFR / NSEC checks).

```bash
cd dns-cloak
PYTHONPATH=src python -m dns_cloak audit example.com
```

JSON:

```bash
PYTHONPATH=src python -m dns_cloak audit example.com --json
```

Allowlist + Cloudflare classify (no deletes):

```bash
export CLOUDFLARE_API_TOKEN=...   # Zone:Read + Zone:DNS:Edit
PYTHONPATH=src python -m dns_cloak audit --policy examples/policy.yaml
PYTHONPATH=src python -m dns_cloak apply --policy examples/policy.yaml
PYTHONPATH=src python -m dns_cloak apply --policy examples/policy.yaml --yes
```

Install as a command:

```bash
pip install -e .
dns-cloak audit example.com
```

Tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Copy `examples/policy.yaml` and list **only** names that should stay public (`@` = apex). Internal apps should not appear in that list.

## Private apps (the real hide)

From [Cloudflare’s own docs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/): private network applications **do not have public DNS records**. Users reach them through the Cloudflare One / WARP client after you attach a tunnel route, not through `secret.example.com` on the public internet.

1. Create a Cloudflare Tunnel (`cloudflared`).
2. Advertise a **private CIDR** (or an internal hostname via Gateway resolver / local domain fallback).
3. Do **not** add a public hostname ingress rule for that app.
4. Put the service behind Access if you want identity, still without a public name.

See `examples/cloudflared-private.yml`.

## Project structure

```text
dns-cloak/
├── src/dns_cloak/       CLI, policy, CT, Cloudflare API, DNS checks
├── examples/            policy.yaml + private tunnel snippet
├── tests/
└── .github/workflows/   unittest on push
```

Stdlib only. Optional network: crt.sh and Cloudflare API.

## Limits you should expect

- Deleting `staging.example.com` today does not remove last year’s CT row.
- If you still need a public URL for staff, use a **separate domain** that you never mention on the marketing site, plus Access — finder tools that are given that domain can still see it.
- DNSSEC `NSEC` can list every name that **is** in the public zone. Prefer `NSEC3` or keep the public zone tiny.

## License

No license file is attached, so others do not have an explicit right to reuse this beyond GitHub’s terms of viewing the repository.
