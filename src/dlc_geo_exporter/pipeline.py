from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import CONFIG, Config
from .domain_service import export_domains
from .geoip_service import export_geoip
from .srs_service import export_srs_geoip


@dataclass
class RunResult:
    domains_file: Path | None
    geoip_file: Path | None
    srs_geoip_file: Path | None


def run_all(cfg: Config = CONFIG) -> RunResult:
    domains_file = export_domains(cfg)
    geoip_file = export_geoip(cfg)
    srs_geoip_file = export_srs_geoip(cfg)
    return RunResult(
        domains_file=domains_file,
        geoip_file=geoip_file,
        srs_geoip_file=srs_geoip_file,
    )
