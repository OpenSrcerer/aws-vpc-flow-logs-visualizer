from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


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


def parse_vpc_flow_log_line(line: str) -> ParsedFlowRecord:
    parts = line.strip().split()
    if len(parts) < 14:
        raise ValueError("Expected at least 14 fields for VPC flow log format")

    version = _to_int(parts[0], default=2) or 2
    account_id = parts[1]
    interface_id = parts[2]
    srcaddr = parts[3]
    dstaddr = parts[4]
    srcport = _to_int(parts[5])
    dstport = _to_int(parts[6])
    protocol = _to_int(parts[7], default=0) or 0
    packets = _to_int(parts[8], default=0) or 0
    bytes_sent = _to_int(parts[9], default=0) or 0
    start_epoch = _to_int(parts[10], default=0) or 0
    end_epoch = _to_int(parts[11], default=start_epoch) or start_epoch
    action = parts[12].upper()
    log_status = parts[13].upper()

    if srcaddr == "-" or dstaddr == "-":
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


def parse_vpc_flow_log_lines(lines: Iterable[str]) -> tuple[list[ParsedFlowRecord], list[dict]]:
    parsed: list[ParsedFlowRecord] = []
    errors: list[dict] = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            parsed.append(parse_vpc_flow_log_line(stripped))
        except (ValueError, TypeError) as exc:
            errors.append({"line": line_number, "error": str(exc), "raw": stripped})

    return parsed, errors
