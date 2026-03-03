from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterable


DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS = (
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
)
DEFAULT_VPC_FLOW_LOG_FORMAT = " ".join(DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS)

_FORMAT_FIELD_ALIASES = {
    "account_id": "account-id",
    "interface_id": "interface-id",
    "log_status": "log-status",
    "start-time": "start",
    "start_time": "start",
    "end-time": "end",
    "end_time": "end",
}


@dataclass
class ParsedFlowRecord:
    version: int
    account_id: str
    interface_id: str
    srcaddr: str
    dstaddr: str
    srcport: int | None
    dstport: int | None
    protocol: int
    packets: int
    bytes: int
    start_time: datetime
    end_time: datetime
    action: str
    log_status: str
    raw_line: str


def _to_int(value: str | None, *, default: int | None = None) -> int | None:
    if value in (None, "", "-"):
        return default
    return int(value)


def _normalize_format_field_name(field_name: str) -> str:
    normalized = str(field_name).strip()
    if normalized.startswith("${") and normalized.endswith("}"):
        normalized = normalized[2:-1].strip()

    normalized = normalized.strip("{}").strip().lower().replace("_", "-")
    return _FORMAT_FIELD_ALIASES.get(normalized, normalized)


def parse_vpc_flow_log_format(log_format: str | Iterable[str] | None = None) -> tuple[str, ...]:
    if log_format is None:
        return DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS

    if isinstance(log_format, str):
        cleaned = log_format.strip()
        if not cleaned:
            return DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS
        raw_fields = cleaned.replace(",", " ").split()
    else:
        raw_fields = list(log_format)

    normalized_fields = [_normalize_format_field_name(field) for field in raw_fields if str(field).strip()]
    if not normalized_fields:
        return DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS

    seen_fields: set[str] = set()
    duplicate_fields: set[str] = set()
    for field in normalized_fields:
        if field in seen_fields:
            duplicate_fields.add(field)
            continue
        seen_fields.add(field)

    duplicates = sorted(duplicate_fields)
    if duplicates:
        raise ValueError(f"Duplicate fields in log_format: {', '.join(duplicates)}")

    missing_required = [field for field in DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS if field not in normalized_fields]
    if missing_required:
        raise ValueError(f"log_format must include required fields: {', '.join(missing_required)}")

    return tuple(normalized_fields)


@lru_cache(maxsize=128)
def _format_field_positions(log_format_fields: tuple[str, ...]) -> dict[str, int]:
    return {field: index for index, field in enumerate(log_format_fields)}


def _missing_field_count_error(expected_count: int) -> str:
    if expected_count == len(DEFAULT_VPC_FLOW_LOG_FORMAT_FIELDS):
        return "Expected at least 14 fields for VPC flow log format"
    return f"Expected at least {expected_count} fields for configured VPC flow log format"


def parse_vpc_flow_log_line(line: str, *, log_format: str | Iterable[str] | tuple[str, ...] | None = None) -> ParsedFlowRecord:
    if isinstance(log_format, tuple):
        format_fields = log_format
    else:
        format_fields = parse_vpc_flow_log_format(log_format)

    parts = line.strip().split()
    if len(parts) < len(format_fields):
        raise ValueError(_missing_field_count_error(len(format_fields)))

    field_positions = _format_field_positions(format_fields)

    version = _to_int(parts[field_positions["version"]], default=2) or 2
    account_id = parts[field_positions["account-id"]]
    interface_id = parts[field_positions["interface-id"]]
    srcaddr = parts[field_positions["srcaddr"]]
    dstaddr = parts[field_positions["dstaddr"]]
    srcport = _to_int(parts[field_positions["srcport"]])
    dstport = _to_int(parts[field_positions["dstport"]])
    protocol = _to_int(parts[field_positions["protocol"]], default=0) or 0
    packets = _to_int(parts[field_positions["packets"]], default=0) or 0
    bytes_sent = _to_int(parts[field_positions["bytes"]], default=0) or 0
    start_epoch = _to_int(parts[field_positions["start"]], default=0) or 0
    end_epoch = _to_int(parts[field_positions["end"]], default=start_epoch) or start_epoch
    action = parts[field_positions["action"]].upper()
    log_status = parts[field_positions["log-status"]].upper()

    if not srcaddr or not dstaddr or srcaddr == "-" or dstaddr == "-":
        raise ValueError("srcaddr and dstaddr are required")

    start_time = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
    end_time = datetime.fromtimestamp(end_epoch, tz=timezone.utc)

    return ParsedFlowRecord(
        version=version,
        account_id=account_id,
        interface_id=interface_id,
        srcaddr=srcaddr,
        dstaddr=dstaddr,
        srcport=srcport,
        dstport=dstport,
        protocol=protocol,
        packets=packets,
        bytes=bytes_sent,
        start_time=start_time,
        end_time=end_time,
        action=action,
        log_status=log_status,
        raw_line=line.rstrip("\n"),
    )


def parse_vpc_flow_log_lines(
    lines: Iterable[str],
    *,
    log_format: str | Iterable[str] | tuple[str, ...] | None = None,
) -> tuple[list[ParsedFlowRecord], list[dict]]:
    format_fields = parse_vpc_flow_log_format(log_format)
    parsed: list[ParsedFlowRecord] = []
    errors: list[dict] = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            parsed.append(parse_vpc_flow_log_line(stripped, log_format=format_fields))
        except (ValueError, TypeError) as exc:
            errors.append({"line": line_number, "error": str(exc), "raw": stripped})

    return parsed, errors
