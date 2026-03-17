from __future__ import annotations

import ipaddress
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import Config


MAGIC = b"SRS"

RULE_TYPE_DEFAULT = 0
RULE_TYPE_LOGICAL = 1

RULE_ITEM_SOURCE_IP_CIDR = 5
RULE_ITEM_IP_CIDR = 6
RULE_ITEM_NETWORK_IS_EXPENSIVE = 19
RULE_ITEM_NETWORK_IS_CONSTRAINED = 20
RULE_ITEM_FINAL = 255


def _download_binary(url: str, timeout_sec: int) -> bytes:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (kotrik exporter tg: @kr_tail)"})
    with urlopen(req, timeout=timeout_sec) as resp:
        return resp.read()


def _read_uvarint(buf: bytes, offset: int) -> tuple[int, int]:
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
            raise ValueError("invalid uvarint")
    raise ValueError("unexpected eof in uvarint")


def _read_bool(buf: bytes, offset: int) -> tuple[bool, int]:
    if offset >= len(buf):
        raise ValueError("unexpected eof in bool")
    return buf[offset] != 0, offset + 1


def _read_u8(buf: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(buf):
        raise ValueError("unexpected eof in u8")
    return buf[offset], offset + 1


def _read_len_prefixed_string_list(buf: bytes, offset: int) -> int:
    length, i = _read_uvarint(buf, offset)
    for _ in range(length):
        item_len, i = _read_uvarint(buf, i)
        i += item_len
        if i > len(buf):
            raise ValueError("unexpected eof in string list")
    return i


def _read_u16_list(buf: bytes, offset: int) -> int:
    length, i = _read_uvarint(buf, offset)
    i += length * 2
    if i > len(buf):
        raise ValueError("unexpected eof in uint16 list")
    return i


def _read_u8_list(buf: bytes, offset: int) -> int:
    length, i = _read_uvarint(buf, offset)
    i += length
    if i > len(buf):
        raise ValueError("unexpected eof in uint8 list")
    return i


def _skip_network_interface_address(buf: bytes, offset: int) -> int:
    size, i = _read_uvarint(buf, offset)
    for _ in range(size):
        _, i = _read_u8(buf, i)
        prefix_count, i = _read_uvarint(buf, i)
        for _ in range(prefix_count):
            i = _skip_prefix(buf, i)
    return i


def _skip_default_interface_address(buf: bytes, offset: int) -> int:
    prefix_count, i = _read_uvarint(buf, offset)
    for _ in range(prefix_count):
        i = _skip_prefix(buf, i)
    return i


def _skip_prefix(buf: bytes, offset: int) -> int:
    addr_len, i = _read_uvarint(buf, offset)
    i += addr_len
    if i >= len(buf):
        raise ValueError("unexpected eof in prefix")
    return i + 1


def _read_ipset_ranges(buf: bytes, offset: int) -> tuple[list[tuple[Any, Any]], int]:
    version, i = _read_u8(buf, offset)
    if version != 1:
        raise ValueError(f"unsupported ipset version: {version}")

    if i + 8 > len(buf):
        raise ValueError("unexpected eof in ipset length")
    range_count = struct.unpack(">Q", buf[i : i + 8])[0]
    i += 8

    ranges: list[tuple[Any, Any]] = []
    for _ in range(range_count):
        from_len, i = _read_uvarint(buf, i)
        from_raw = buf[i : i + from_len]
        i += from_len
        to_len, i = _read_uvarint(buf, i)
        to_raw = buf[i : i + to_len]
        i += to_len
        if i > len(buf):
            raise ValueError("unexpected eof in ipset range")

        start = ipaddress.ip_address(from_raw)
        end = ipaddress.ip_address(to_raw)
        ranges.append((start, end))

    return ranges, i


def _ranges_to_cidrs(ranges: list[tuple[Any, Any]]) -> list[str]:
    cidrs: list[str] = []
    for start, end in ranges:
        for network in ipaddress.summarize_address_range(start, end):
            cidrs.append(str(network))
    return cidrs


def _parse_default_rule_for_cidrs(buf: bytes, offset: int) -> tuple[list[str], int]:
    cidrs: list[str] = []
    i = offset

    while True:
        item_type, i = _read_u8(buf, i)

        if item_type == RULE_ITEM_SOURCE_IP_CIDR or item_type == RULE_ITEM_IP_CIDR:
            ranges, i = _read_ipset_ranges(buf, i)
            cidrs.extend(_ranges_to_cidrs(ranges))
            continue

        if item_type == RULE_ITEM_FINAL:
            _, i = _read_bool(buf, i)
            return cidrs, i

        if item_type in (0, 7, 9):
            i = _read_u16_list(buf, i)
            continue
        if item_type in (1, 3, 4, 8, 10, 11, 12, 13, 14, 15, 17):
            i = _read_len_prefixed_string_list(buf, i)
            continue
        if item_type == 18:
            i = _read_u8_list(buf, i)
            continue
        if item_type in (RULE_ITEM_NETWORK_IS_EXPENSIVE, RULE_ITEM_NETWORK_IS_CONSTRAINED):
            continue
        if item_type == 21:
            i = _skip_network_interface_address(buf, i)
            continue
        if item_type == 22:
            i = _skip_default_interface_address(buf, i)
            continue

        raise ValueError(f"unsupported rule item in SRS parser: {item_type}")


def _parse_rule_for_cidrs(buf: bytes, offset: int) -> tuple[list[str], int]:
    rule_type, i = _read_u8(buf, offset)

    if rule_type == RULE_TYPE_DEFAULT:
        return _parse_default_rule_for_cidrs(buf, i)

    if rule_type == RULE_TYPE_LOGICAL:
        _, i = _read_u8(buf, i)  # logical mode
        length, i = _read_uvarint(buf, i)
        cidrs: list[str] = []
        for _ in range(length):
            child, i = _parse_rule_for_cidrs(buf, i)
            cidrs.extend(child)
        _, i = _read_bool(buf, i)
        return cidrs, i

    raise ValueError(f"unsupported SRS rule type: {rule_type}")


def _parse_srs_cidrs(data: bytes) -> list[str]:
    if len(data) < 4 or data[:3] != MAGIC:
        raise ValueError("invalid SRS file header")

    compressed = data[4:]
    payload = zlib.decompress(compressed)

    rule_count, i = _read_uvarint(payload, 0)
    cidrs: list[str] = []
    for _ in range(rule_count):
        current, i = _parse_rule_for_cidrs(payload, i)
        cidrs.extend(current)

    return cidrs


@dataclass
class _CategoryResult:
    category: str
    values: list[str]


def _extract_geoip_category(cfg: Config, category: str) -> _CategoryResult | None:
    last_error: Exception | None = None

    for source in cfg.srs_geoip_sources:
        url = source.url_template.format(category=category)
        try:
            raw = _download_binary(url, cfg.download_timeout_sec)
            values = _parse_srs_cidrs(raw)
            return _CategoryResult(category=category, values=values)
        except HTTPError as exc:
            if exc.code == 404:
                last_error = exc
                continue
            raise
        except URLError as exc:
            last_error = exc
            continue
        except Exception as exc:
            last_error = exc
            break

    if cfg.strict_lists:
        if last_error is None:
            raise ValueError(f"SRS category not found: {category}")
        raise ValueError(f"Failed to fetch/parse SRS category '{category}': {last_error}")

    return None


def export_srs_geoip(cfg: Config) -> Path:
    seen: set[str] = set()
    cidrs: list[str] = []

    for category in cfg.srs_geoip_categories:
        result = _extract_geoip_category(cfg, category)
        if result is None:
            continue
        for value in result.values:
            if cfg.geoip_only_ip_type == "ipv4" and ":" in value:
                continue
            if cfg.geoip_only_ip_type == "ipv6" and ":" not in value:
                continue
            if value in seen:
                continue
            seen.add(value)
            cidrs.append(value)

    if cfg.sort_output:
        cidrs.sort()

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = cfg.output_dir / cfg.srs_geoip_output_file
    output_path.write_text("\n".join(cidrs) + ("\n" if cidrs else ""), encoding="utf-8")
    return output_path
