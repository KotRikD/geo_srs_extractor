from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SrsGeoIPSource:
    url_template: str


@dataclass(frozen=True)
class Config:
    domain_yaml_url: str = (
        "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml"
    )
    geoip_dat_url: str = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"

    domain_categories: tuple[str, ...] = (
        "category-ai-!cn",
        "twitter",
        "blizzard",
        "mongodb",
        "discord",
        "spotify",
        "vrchat",
        "vrcdn",
        "instagram",
        "tiktok",
    )
    geoip_lists: tuple[str, ...] = ()

    output_dir: Path = Path("output")
    domain_output_file: str = "domains.txt"
    geoip_output_file: str = "geoip.txt"
    srs_geoip_output_file: str = "srs_geoip.txt"

    include_domain_rule_types: tuple[str, ...] = ("domain", "full")
    sort_output: bool = True

    download_timeout_sec: int = 60
    strict_lists: bool = False

    geoip_only_ip_type: str | None = None  # None | "ipv4" | "ipv6"

    # SRS GeoIP extraction (multi-source).
    srs_geoip_categories: tuple[str, ...] = ("openai",)
    srs_geoip_sources: tuple[SrsGeoIPSource, ...] = (
        SrsGeoIPSource(
            url_template=(
                "https://cdn.jsdelivr.net/gh/chocolate4u/"
                "Iran-sing-box-rules@rule-set/geoip-{category}.srs"
            )
        ),
    )


CONFIG = Config()
