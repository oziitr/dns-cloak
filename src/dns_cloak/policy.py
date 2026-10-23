from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re


KEEP_TYPES_DEFAULT = ("NS", "SOA")

_FQDN_RE = re.compile(r"^[a-z0-9._*-]+$", re.IGNORECASE)


@dataclass(frozen=True)
class Policy:
    domain: str
    public: tuple[str, ...]
    keep_types: tuple[str, ...] = KEEP_TYPES_DEFAULT
    keep_names: tuple[str, ...] = field(default_factory=tuple)

    @property
    def apex(self) -> str:
        return self.domain.lower().rstrip(".")

    def public_fqdns(self) -> set[str]:
        apex = self.apex
        names: set[str] = set()
        for raw in self.public:
            label = raw.strip().lower().rstrip(".")
            if not label or label in {"@", apex}:
                names.add(apex)
                continue
            if label.endswith("." + apex) or label == apex:
                names.add(label)
            else:
                names.add(f"{label}.{apex}")
        names.update(n.lower().rstrip(".") for n in self.keep_names)
        return names

    def is_public_name(self, fqdn: str) -> bool:
        name = fqdn.lower().rstrip(".")
        apex = self.apex
        if name in self.public_fqdns():
            return True
        # Wildcard allow: "*.example.com" covers one label under apex.
        for allowed in self.public_fqdns():
            if allowed.startswith("*."):
                suffix = allowed[1:]  # ".example.com"
                rest = name[: -len(suffix)] if name.endswith(suffix) else ""
                if rest and "." not in rest:
                    return True
        if name.endswith("." + apex):
            return False
        return name == apex


def load_policy(path: str | Path) -> Policy:
    text = Path(path).read_text(encoding="utf-8")
    data = _parse_simple_yaml(text)
    domain = str(data.get("domain", "")).strip().lower()
    if not domain or not _FQDN_RE.match(domain):
        raise ValueError("policy.yaml needs a valid `domain:` field")
    public = tuple(str(x).strip() for x in data.get("public") or [] if str(x).strip())
    keep_types = tuple(
        str(x).strip().upper()
        for x in (data.get("keep_types") or KEEP_TYPES_DEFAULT)
        if str(x).strip()
    )
    keep_names = tuple(
        str(x).strip().lower()
        for x in data.get("keep_names") or []
        if str(x).strip()
    )
    return Policy(domain=domain, public=public, keep_types=keep_types, keep_names=keep_names)


def _parse_simple_yaml(text: str) -> dict:
    """Tiny YAML subset: domain, lists of scalars. Avoids a PyYAML dependency."""
    result: dict = {}
    current_list: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.split("#", 1)[0]
        if not stripped.strip():
            continue
        line = stripped.rstrip()
        if re.match(r"^[A-Za-z_][\w-]*:\s*$", line):
            key = line[:-1].strip()
            result[key] = []
            current_list = key
            continue
        m = re.match(r"^([A-Za-z_][\w-]*):\s+(.+)$", line)
        if m:
            result[m.group(1)] = _scalar(m.group(2))
            current_list = None
            continue
        if current_list and re.match(r"^\s+-\s+", line):
            item = re.sub(r"^\s+-\s+", "", line).strip()
            if item in {"[]", ""}:
                continue
            result.setdefault(current_list, []).append(_scalar(item))
            continue
        current_list = None
    return result


def _scalar(value: str):
    value = value.strip().strip('"').strip("'")
    if value == "[]":
        return []
    return value
