from __future__ import annotations

from pathlib import Path
from urllib.request import Request, urlopen

import yaml

from .config import Config


def _download_text(url: str, timeout_sec: int) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (kotrik exporter tg: @kr_tail)"})
    with urlopen(req, timeout=timeout_sec) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def _parse_rule(rule: str) -> tuple[str | None, str | None]:
    parts = rule.split(":")
    if len(parts) < 2:
        return None, None
    return parts[0].strip(), parts[1].strip()


def export_domains(cfg: Config) -> Path:
    raw = _download_text(cfg.domain_yaml_url, cfg.download_timeout_sec)
    data = yaml.safe_load(raw)
    lists = data.get("lists", []) if isinstance(data, dict) else []

    by_name: dict[str, list[str]] = {}
    for item in lists:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        rules = item.get("rules", [])
        if isinstance(name, str) and isinstance(rules, list):
            by_name[name] = [str(x) for x in rules]

    missing = [name for name in cfg.domain_categories if name not in by_name]
    if missing and cfg.strict_lists:
        raise ValueError(f"Domain categories not found: {', '.join(missing)}")

    rule_types = set(cfg.include_domain_rule_types)
    seen: set[str] = set()
    result: list[str] = []

    for category in cfg.domain_categories:
        for rule in by_name.get(category, []):
            rule_type, value = _parse_rule(rule)
            if not rule_type or not value:
                continue
            if rule_type not in rule_types:
                continue
            if value in seen:
                continue
            seen.add(value)
            result.append(value)

    if cfg.sort_output:
        result.sort()

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = cfg.output_dir / cfg.domain_output_file
    output_path.write_text("\n".join(result) + ("\n" if result else ""), encoding="utf-8")
    return output_path
