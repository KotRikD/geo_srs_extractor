from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dlc_geo_exporter.config import CONFIG
from dlc_geo_exporter.pipeline import run_all


def main() -> None:
    try:
        result = run_all(CONFIG)
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1) from exc

    print(f"Domains exported to: {result.domains_file}")
    print(f"GeoIP exported to: {result.geoip_file}")
    print(f"SRS GeoIP exported to: {result.srs_geoip_file}")


if __name__ == "__main__":
    main()
