from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.request import Request, urlopen

from .config import Config


def _download_binary(url: str, timeout_sec: int) -> bytes:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (kotrik exporter tg: @kr_tail)"})
    with urlopen(req, timeout=timeout_sec) as resp:
        return resp.read()


def _read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    i = offset
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, i
        shift += 7
        if shift >= 64:
            raise ValueError("Invalid varint in protobuf")
    raise ValueError("Unexpected EOF while reading varint")


def _read_key(buf: bytes, offset: int) -> tuple[int, int, int]:
    key, new_offset = _read_varint(buf, offset)
    field_number = key >> 3
    wire_type = key & 0x07
    if field_number == 0:
        raise ValueError("Invalid protobuf field number 0")
    return field_number, wire_type, new_offset


def _read_len_delimited(buf: bytes, offset: int) -> tuple[bytes, int]:
    length, i = _read_varint(buf, offset)
    end = i + length
    if end > len(buf):
        raise ValueError("Unexpected EOF while reading length-delimited field")
    return buf[i:end], end


def _skip_field(buf: bytes, wire_type: int, offset: int) -> int:
    if wire_type == 0:
        _, i = _read_varint(buf, offset)
        return i
    if wire_type == 1:
        i = offset + 8
        if i > len(buf):
            raise ValueError("Unexpected EOF while skipping fixed64")
        return i
    if wire_type == 2:
        _, i = _read_len_delimited(buf, offset)
        return i
    if wire_type == 5:
        i = offset + 4
        if i > len(buf):
            raise ValueError("Unexpected EOF while skipping fixed32")
        return i
    raise ValueError(f"Unsupported protobuf wire type: {wire_type}")


def _parse_cidr(message: bytes) -> tuple[bytes | None, int | None]:
    ip_raw: bytes | None = None
    prefix: int | None = None

    i = 0
    while i < len(message):
        field_no, wire_type, i = _read_key(message, i)
        if field_no == 1 and wire_type == 2:
            ip_raw, i = _read_len_delimited(message, i)
            continue
        if field_no == 2 and wire_type == 0:
            prefix, i = _read_varint(message, i)
            continue
        i = _skip_field(message, wire_type, i)

    return ip_raw, prefix


def _normalize_cidr(ip_raw: bytes, prefix: int) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(ip_raw)
    except ValueError:
        return None

    max_prefix = 32 if ip_obj.version == 4 else 128
    if prefix < 0 or prefix > max_prefix:
        return None

    network = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
    return str(network)


def _parse_geoip_entry(message: bytes) -> tuple[set[str], list[str]]:
    country_code = ""
    code = ""
    cidrs: list[str] = []

    i = 0
    while i < len(message):
        field_no, wire_type, i = _read_key(message, i)

        if field_no == 1 and wire_type == 2:
            raw, i = _read_len_delimited(message, i)
            country_code = raw.decode("utf-8", errors="ignore").strip()
            continue

        if field_no == 2 and wire_type == 2:
            raw, i = _read_len_delimited(message, i)
            ip_raw, prefix = _parse_cidr(raw)
            if ip_raw is None or prefix is None:
                continue
            cidr = _normalize_cidr(ip_raw, prefix)
            if cidr is not None:
                cidrs.append(cidr)
            continue

        if field_no == 5 and wire_type == 2:
            raw, i = _read_len_delimited(message, i)
            code = raw.decode("utf-8", errors="ignore").strip()
            continue

        i = _skip_field(message, wire_type, i)

    names = {name.lower() for name in (country_code, code) if name}
    return names, cidrs


def _parse_geoip_dat(data: bytes) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}

    i = 0
    while i < len(data):
        field_no, wire_type, i = _read_key(data, i)
        if field_no == 1 and wire_type == 2:
            raw, i = _read_len_delimited(data, i)
            names, cidrs = _parse_geoip_entry(raw)
            if not names:
                continue
            for name in names:
                result.setdefault(name, []).extend(cidrs)
            continue
        i = _skip_field(data, wire_type, i)

    return result


def export_geoip(cfg: Config) -> Path:
    data = _download_binary(cfg.geoip_dat_url, cfg.download_timeout_sec)
    parsed = _parse_geoip_dat(data)

    requested = list(cfg.geoip_lists)
    requested_lc = [name.lower() for name in requested]

    seen: set[str] = set()
    cidrs: list[str] = []
    missing: list[str] = []

    for original_name, list_name in zip(requested, requested_lc):
        values = parsed.get(list_name)
        if not values:
            missing.append(original_name)
            continue

        for value in values:
            if cfg.geoip_only_ip_type == "ipv4" and ":" in value:
                continue
            if cfg.geoip_only_ip_type == "ipv6" and ":" not in value:
                continue
            if value in seen:
                continue
            seen.add(value)
            cidrs.append(value)

    if missing and cfg.strict_lists:
        raise ValueError(f"GeoIP lists not found: {', '.join(missing)}")

    if cfg.sort_output:
        cidrs.sort()

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = cfg.output_dir / cfg.geoip_output_file
    output_path.write_text("\n".join(cidrs) + ("\n" if cidrs else ""), encoding="utf-8")
    return output_path
