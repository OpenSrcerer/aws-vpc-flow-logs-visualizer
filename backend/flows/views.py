import gzip
import io
from contextlib import ExitStack
from itertools import islice

from django.db import IntegrityError, transaction
from django.db import connection
from django.db.models import BigIntegerField, Count, F, Max, Min, Q, Sum
from django.utils.dateparse import parse_datetime
from rest_framework import status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from .advanced_filters import (
    AdvancedFilterError,
    advanced_filter_can_run_in_db,
    build_prefilter_q_from_advanced_filter_ast,
    evaluate_advanced_filter,
    inject_instance_context,
    parse_advanced_filter,
    validate_advanced_filter_ast,
)
from .models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup
from .parsers import parse_vpc_flow_log_line
from .serializers import (
    CorrelatedFlowSerializer,
    FlowLogEntrySerializer,
    FlowLogUploadSerializer,
    IpMetadataImportSerializer,
    IpMetadataSerializer,
    NetworkGroupImportSerializer,
    NetworkGroupSerializer,
)
from .services import (
    build_firewall_recommendations,
    build_mesh_payload,
    parsed_records_to_entries,
    rebuild_correlated_flows,
    upsert_correlated_flows,
)

ADVANCED_FILTER_CHUNK_SIZE = 2000
ADVANCED_FILTER_SCAN_LIMIT = 100_000
FLOW_LOG_PARSE_BATCH_SIZE = 5000
FLOW_LOG_PARSE_ERROR_SAMPLE_LIMIT = 100
SQLITE_VARIABLE_LIMIT = 900


def _chunks(iterable, size):
    iterator = iter(iterable)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            return
        yield chunk


def _safe_int(value, *, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default

    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


class HealthView(APIView):
    def get(self, request):
        return Response(
            {
                "status": "ok",
                "flow_log_entries": FlowLogEntry.objects.count(),
                "correlated_flows": CorrelatedFlow.objects.count(),
                "ip_metadata": IpMetadata.objects.count(),
                "network_groups": NetworkGroup.objects.count(),
            }
        )


class DashboardSummaryView(APIView):
    def get(self, request):
        total_bytes_expr = F("c2s_bytes") + F("s2c_bytes")
        total_packets_expr = F("c2s_packets") + F("s2c_packets")

        totals = CorrelatedFlow.objects.aggregate(
            total_bytes=Sum(total_bytes_expr, output_field=BigIntegerField()),
            total_packets=Sum(total_packets_expr, output_field=BigIntegerField()),
            total_sessions=Sum("flow_count", output_field=BigIntegerField()),
        )

        protocol_rows = (
            CorrelatedFlow.objects.values("protocol")
            .annotate(total_bytes=Sum(total_bytes_expr, output_field=BigIntegerField()))
            .order_by("-total_bytes", "protocol")[:6]
        )

        protocol_breakdown = [
            {
                "protocol": row["protocol"],
                "bytes": int(row["total_bytes"] or 0),
            }
            for row in protocol_rows
        ]

        return Response(
            {
                "traffic": {
                    "total_bytes": int(totals.get("total_bytes") or 0),
                    "total_packets": int(totals.get("total_packets") or 0),
                    "total_sessions": int(totals.get("total_sessions") or 0),
                },
                "protocol_breakdown": protocol_breakdown,
            }
        )


class GlobalSearchView(APIView):
    def get(self, request):
        query = str(request.query_params.get("q", "")).strip()
        if not query:
            return Response(
                {
                    "query": "",
                    "limit": 25,
                    "counts": {
                        "flow_logs": 0,
                        "correlated_flows": 0,
                        "ip_metadata": 0,
                        "network_groups": 0,
                    },
                    "results": {
                        "flow_logs": [],
                        "correlated_flows": [],
                        "ip_metadata": [],
                        "network_groups": [],
                    },
                }
            )

        try:
            limit = max(1, min(int(request.query_params.get("limit", 25)), 100))
        except ValueError:
            limit = 25

        protocol_alias_map = {
            "icmp": 1,
            "ipip": 4,
            "ip-in-ip": 4,
            "ip_in_ip": 4,
            "ipinip": 4,
            "tcp": 6,
            "udp": 17,
        }
        protocol_number = protocol_alias_map.get(query.lower())
        integer_query = None
        try:
            integer_query = int(query)
        except ValueError:
            integer_query = None

        flow_log_filter = (
            Q(srcaddr__icontains=query)
            | Q(dstaddr__icontains=query)
            | Q(account_id__icontains=query)
            | Q(interface_id__icontains=query)
            | Q(source__icontains=query)
            | Q(action__icontains=query)
            | Q(log_status__icontains=query)
        )
        correlated_flow_filter = (
            Q(client_ip__icontains=query)
            | Q(server_ip__icontains=query)
            | Q(canonical_key__icontains=query)
        )
        ip_metadata_filter = (
            Q(ip_address__icontains=query)
            | Q(name__icontains=query)
            | Q(asset_kind__icontains=query)
            | Q(instance_id__icontains=query)
            | Q(interface_id__icontains=query)
            | Q(instance_type__icontains=query)
            | Q(state__icontains=query)
            | Q(region__icontains=query)
            | Q(availability_zone__icontains=query)
            | Q(account_owner__icontains=query)
            | Q(provider__icontains=query)
            | Q(tags__icontains=query)
        )
        network_group_filter = (
            Q(name__icontains=query)
            | Q(kind__icontains=query)
            | Q(cidr__icontains=query)
            | Q(cidrs__icontains=query)
            | Q(tags__icontains=query)
            | Q(description__icontains=query)
        )

        if integer_query is not None:
            flow_log_filter |= Q(srcport=integer_query) | Q(dstport=integer_query) | Q(protocol=integer_query)
            correlated_flow_filter |= (
                Q(client_port=integer_query) | Q(server_port=integer_query) | Q(protocol=integer_query)
            )

        if protocol_number is not None:
            flow_log_filter |= Q(protocol=protocol_number)
            correlated_flow_filter |= Q(protocol=protocol_number)

        flow_logs = (
            FlowLogEntry.objects.filter(flow_log_filter)
            .order_by("-start_time", "-id")[:limit]
        )
        correlated_flows = (
            CorrelatedFlow.objects.filter(correlated_flow_filter)
            .order_by("-last_seen", "-id")[:limit]
        )
        ip_metadata = (
            IpMetadata.objects.filter(ip_metadata_filter)
            .order_by("ip_address")[:limit]
        )
        network_groups = (
            NetworkGroup.objects.filter(network_group_filter)
            .order_by("name")[:limit]
        )

        return Response(
            {
                "query": query,
                "limit": limit,
                "counts": {
                    "flow_logs": len(flow_logs),
                    "correlated_flows": len(correlated_flows),
                    "ip_metadata": len(ip_metadata),
                    "network_groups": len(network_groups),
                },
                "results": {
                    "flow_logs": FlowLogEntrySerializer(flow_logs, many=True).data,
                    "correlated_flows": CorrelatedFlowSerializer(correlated_flows, many=True).data,
                    "ip_metadata": IpMetadataSerializer(ip_metadata, many=True).data,
                    "network_groups": NetworkGroupSerializer(network_groups, many=True).data,
                },
            }
        )


class FlowLogEntryViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = FlowLogEntrySerializer
    queryset = FlowLogEntry.objects.order_by("-start_time", "-id")

    def get_queryset(self):
        self._manual_filtered_ids = None
        queryset = super().get_queryset()

        srcaddr = self.request.query_params.get("srcaddr")
        dstaddr = self.request.query_params.get("dstaddr")
        action = self.request.query_params.get("action")
        protocol = self.request.query_params.get("protocol")
        since = self.request.query_params.get("since")
        until = self.request.query_params.get("until")
        advanced_filter = (
            self.request.query_params.get("advanced_filter")
            or self.request.query_params.get("filter_expr")
            or self.request.query_params.get("query")
        )

        if srcaddr:
            queryset = queryset.filter(srcaddr=srcaddr)
        if dstaddr:
            queryset = queryset.filter(dstaddr=dstaddr)
        if action:
            queryset = queryset.filter(action__iexact=action)
        if protocol:
            queryset = queryset.filter(protocol=protocol)

        if since:
            parsed = parse_datetime(since)
            if parsed:
                queryset = queryset.filter(start_time__gte=parsed)
        if until:
            parsed = parse_datetime(until)
            if parsed:
                queryset = queryset.filter(end_time__lte=parsed)

        if advanced_filter:
            try:
                ast = parse_advanced_filter(advanced_filter)
                validate_advanced_filter_ast(ast)
            except AdvancedFilterError as exc:
                raise ValidationError({"advanced_filter": str(exc)}) from exc

            prefilter_q = build_prefilter_q_from_advanced_filter_ast(ast)
            if prefilter_q is not None:
                queryset = queryset.filter(prefilter_q)
                if advanced_filter_can_run_in_db(ast):
                    return queryset

            candidate_rows = queryset.values(
                "id",
                "srcaddr",
                "dstaddr",
                "srcport",
                "dstport",
                "protocol",
                "action",
                "source",
                "interface_id",
                "log_status",
            )
            scan_limit_param = self.request.query_params.get("scan_limit")
            if scan_limit_param:
                scan_limit = _safe_int(
                    scan_limit_param,
                    default=ADVANCED_FILTER_SCAN_LIMIT,
                    minimum=1,
                    maximum=1_000_000,
                )
                candidate_rows = candidate_rows[:scan_limit]

            matching_ids = []
            metadata_fields = (
                "ip_address",
                "name",
                "account_owner",
                "region",
                "availability_zone",
                "instance_id",
                "interface_id",
                "instance_type",
                "state",
                "provider",
                "asset_kind",
                "tags",
            )

            row_iterator = candidate_rows.iterator(chunk_size=ADVANCED_FILTER_CHUNK_SIZE)
            for row_chunk in _chunks(row_iterator, ADVANCED_FILTER_CHUNK_SIZE):
                chunk_ips: set[str] = set()
                for row in row_chunk:
                    src_ip = row.get("srcaddr")
                    dst_ip = row.get("dstaddr")
                    if src_ip:
                        chunk_ips.add(str(src_ip))
                    if dst_ip:
                        chunk_ips.add(str(dst_ip))

                metadata_by_ip: dict[str, dict] = {}
                if chunk_ips:
                    metadata_rows = IpMetadata.objects.filter(ip_address__in=chunk_ips).values(*metadata_fields)
                    for metadata_row in metadata_rows.iterator(chunk_size=ADVANCED_FILTER_CHUNK_SIZE):
                        metadata_by_ip[str(metadata_row["ip_address"])] = metadata_row

                for row in row_chunk:
                    inject_instance_context(
                        row,
                        src_meta=metadata_by_ip.get(str(row.get("srcaddr"))),
                        dst_meta=metadata_by_ip.get(str(row.get("dstaddr"))),
                    )
                    try:
                        if evaluate_advanced_filter(ast, row):
                            matching_ids.append(row["id"])
                    except AdvancedFilterError as exc:
                        raise ValidationError({"advanced_filter": str(exc)}) from exc

            if not matching_ids:
                return queryset.none()
            self._manual_filtered_ids = matching_ids
            if connection.vendor == "sqlite" and len(matching_ids) > SQLITE_VARIABLE_LIMIT:
                return queryset
            queryset = queryset.filter(id__in=matching_ids)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        manual_filtered_ids = getattr(self, "_manual_filtered_ids", None)

        if (
            manual_filtered_ids is not None
            and connection.vendor == "sqlite"
            and len(manual_filtered_ids) > SQLITE_VARIABLE_LIMIT
        ):
            page_ids = self.paginate_queryset(manual_filtered_ids)
            if page_ids is not None:
                rows_by_id = {
                    row.id: row
                    for row in FlowLogEntry.objects.filter(id__in=page_ids)
                }
                ordered_rows = [rows_by_id[row_id] for row_id in page_ids if row_id in rows_by_id]
                serializer = self.get_serializer(ordered_rows, many=True)
                return self.get_paginated_response(serializer.data)

            rows_by_id = {
                row.id: row
                for row in FlowLogEntry.objects.filter(id__in=manual_filtered_ids)
            }
            ordered_rows = [rows_by_id[row_id] for row_id in manual_filtered_ids if row_id in rows_by_id]
            serializer = self.get_serializer(ordered_rows, many=True)
            return Response(serializer.data)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class AdvancedFlowFilterValidateView(APIView):
    def post(self, request):
        expression = request.data.get("advanced_filter", "")
        if not isinstance(expression, str):
            return Response(
                {
                    "valid": False,
                    "error": "`advanced_filter` must be a string.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        expression = expression.strip()
        if not expression:
            return Response({"valid": True, "empty": True})

        try:
            ast = parse_advanced_filter(expression)
            validate_advanced_filter_ast(ast)
        except AdvancedFilterError as exc:
            return Response(
                {"valid": False, "error": str(exc)}, status=status.HTTP_400_BAD_REQUEST
            )

        return Response({"valid": True})


class CorrelatedFlowViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CorrelatedFlowSerializer
    queryset = CorrelatedFlow.objects.order_by("-last_seen", "-id")

    def get_queryset(self):
        queryset = super().get_queryset()

        client_ip = self.request.query_params.get("client_ip")
        server_ip = self.request.query_params.get("server_ip")
        protocol = self.request.query_params.get("protocol")
        min_bytes = self.request.query_params.get("min_bytes")

        if client_ip:
            queryset = queryset.filter(client_ip=client_ip)
        if server_ip:
            queryset = queryset.filter(server_ip=server_ip)
        if protocol:
            queryset = queryset.filter(protocol=protocol)
        if min_bytes:
            try:
                threshold = int(min_bytes)
                queryset = queryset.annotate(
                    total_bytes=F("c2s_bytes") + F("s2c_bytes")
                ).filter(total_bytes__gte=threshold)
            except ValueError:
                pass

        return queryset


class IpMetadataViewSet(viewsets.ModelViewSet):
    serializer_class = IpMetadataSerializer
    queryset = IpMetadata.objects.order_by("ip_address")


class NetworkGroupViewSet(viewsets.ModelViewSet):
    serializer_class = NetworkGroupSerializer
    queryset = NetworkGroup.objects.order_by("name")


def _iter_uploaded_flow_lines(uploaded_file):
    file_name = (getattr(uploaded_file, "name", "") or "").lower()
    uploaded_file.open(mode="rb")
    uploaded_file.seek(0)
    magic = uploaded_file.read(2)
    uploaded_file.seek(0)

    is_gzip = file_name.endswith(".gz") or magic == b"\x1f\x8b"
    source_stream = uploaded_file.file if hasattr(uploaded_file, "file") else uploaded_file

    with ExitStack() as stack:
        binary_stream = source_stream
        if is_gzip:
            try:
                binary_stream = stack.enter_context(gzip.GzipFile(fileobj=source_stream, mode="rb"))
            except (OSError, EOFError) as exc:
                raise ValueError("Uploaded gzip file could not be decompressed.") from exc

        text_stream = stack.enter_context(io.TextIOWrapper(binary_stream, encoding="utf-8"))
        try:
            for line in text_stream:
                yield line
        except UnicodeDecodeError as exc:
            raise ValueError("Uploaded flow log file is not valid UTF-8 text.") from exc
        except (OSError, EOFError) as exc:
            if is_gzip:
                raise ValueError("Uploaded gzip file could not be decompressed.") from exc
            raise


def _flush_flow_record_batch(
    records: list,
    *,
    source: str,
    auto_correlate: bool,
) -> tuple[int, dict[str, int]]:
    if not records:
        return 0, {"created": 0, "updated": 0}

    entries = parsed_records_to_entries(records, source=source)
    FlowLogEntry.objects.bulk_create(entries, batch_size=FLOW_LOG_PARSE_BATCH_SIZE)

    correlation = {"created": 0, "updated": 0}
    if auto_correlate:
        correlation = upsert_correlated_flows(entries)

    ingested = len(entries)
    records.clear()
    return ingested, correlation


def _ingest_flow_line_iter(
    lines,
    *,
    source: str,
    auto_correlate: bool,
    log_format: tuple[str, ...] | None = None,
    error_prefix: str = "",
) -> dict:
    parse_errors: list[str | dict] = []
    parse_error_count = 0
    ingested = 0
    correlation = {"created": 0, "updated": 0}
    record_batch = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        try:
            record_batch.append(parse_vpc_flow_log_line(stripped, log_format=log_format))
        except (ValueError, TypeError) as exc:
            parse_error_count += 1
            if len(parse_errors) < FLOW_LOG_PARSE_ERROR_SAMPLE_LIMIT:
                error_item: str | dict = {
                    "line": line_number,
                    "error": str(exc),
                    "raw": stripped,
                }
                if error_prefix:
                    error_item = f"{error_prefix}: {error_item}"
                parse_errors.append(error_item)
            continue

        if len(record_batch) >= FLOW_LOG_PARSE_BATCH_SIZE:
            batch_ingested, batch_correlation = _flush_flow_record_batch(
                record_batch,
                source=source,
                auto_correlate=auto_correlate,
            )
            ingested += batch_ingested
            correlation["created"] += batch_correlation.get("created", 0)
            correlation["updated"] += batch_correlation.get("updated", 0)

    if record_batch:
        batch_ingested, batch_correlation = _flush_flow_record_batch(
            record_batch,
            source=source,
            auto_correlate=auto_correlate,
        )
        ingested += batch_ingested
        correlation["created"] += batch_correlation.get("created", 0)
        correlation["updated"] += batch_correlation.get("updated", 0)

    return {
        "ingested": ingested,
        "parse_error_count": parse_error_count,
        "parse_errors": parse_errors,
        "correlation": correlation,
    }


class FlowLogUploadView(APIView):
    def post(self, request):
        serializer = FlowLogUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        source = serializer.validated_data.get("source", "")
        auto_correlate = serializer.validated_data.get("auto_correlate", True)
        log_format = serializer.validated_data.get("log_format")
        single_file = serializer.validated_data.get("file")
        declared_files = serializer.validated_data.get("files") or []
        uploaded_files = []
        if single_file is not None:
            uploaded_files.append(single_file)

        # Support both a declared `files` list and repeated multipart fields.
        request_files = request.FILES.getlist("files")
        seen_ids: set[int] = set()
        for uploaded in [*declared_files, *request_files]:
            marker = id(uploaded)
            if marker in seen_ids:
                continue
            seen_ids.add(marker)
            uploaded_files.append(uploaded)

        parse_errors: list[str | dict] = []
        parse_error_count = 0
        ingested_total = 0
        correlation_stats = {"created": 0, "updated": 0}
        file_results: list[dict] = []

        def _consume_ingest_result(result: dict) -> None:
            nonlocal parse_error_count, ingested_total
            ingested_total += result.get("ingested", 0)
            parse_error_count += result.get("parse_error_count", 0)
            correlation_stats["created"] += result.get("correlation", {}).get("created", 0)
            correlation_stats["updated"] += result.get("correlation", {}).get("updated", 0)
            remaining = FLOW_LOG_PARSE_ERROR_SAMPLE_LIMIT - len(parse_errors)
            if remaining > 0:
                parse_errors.extend(result.get("parse_errors", [])[:remaining])

        for uploaded in uploaded_files:
            try:
                result = _ingest_flow_line_iter(
                    _iter_uploaded_flow_lines(uploaded),
                    source=source,
                    auto_correlate=auto_correlate,
                    log_format=log_format,
                    error_prefix=uploaded.name,
                )
            except ValueError as exc:
                result = {
                    "ingested": 0,
                    "parse_error_count": 1,
                    "parse_errors": [f"{uploaded.name}: {exc}"],
                    "correlation": {"created": 0, "updated": 0},
                }

            _consume_ingest_result(result)
            file_results.append({
                "name": uploaded.name,
                "ingested": result.get("ingested", 0),
                "parse_error_count": result.get("parse_error_count", 0),
            })

        lines_payload = serializer.validated_data.get("lines", "")
        if lines_payload:
            result = _ingest_flow_line_iter(
                io.StringIO(lines_payload),
                source=source,
                auto_correlate=auto_correlate,
                log_format=log_format,
            )
            _consume_ingest_result(result)
            file_results.append(
                {
                    "name": "(pasted-lines)",
                    "ingested": result.get("ingested", 0),
                    "parse_error_count": result.get("parse_error_count", 0),
                }
            )

        return Response(
            {
                "ingested": ingested_total,
                "ingested_files": len(file_results),
                "file_results": file_results,
                "parse_errors": parse_errors,
                "parse_error_count": parse_error_count,
                "correlation": correlation_stats,
            },
            status=status.HTTP_201_CREATED,
        )


class CorrelationRebuildView(APIView):
    def post(self, request):
        batch_size = request.data.get("batch_size", 2000)
        try:
            batch_size_int = int(batch_size)
        except (TypeError, ValueError):
            batch_size_int = 2000

        stats = rebuild_correlated_flows(batch_size=batch_size_int)
        return Response({"status": "ok", "rebuild": stats})


class IpMetadataImportView(APIView):
    def post(self, request):
        serializer = IpMetadataImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        created = 0
        updated = 0

        items_data = serializer.validated_data["items"]
        if not items_data:
            return Response({"created": 0, "updated": 0})

        unique_items = {item["ip_address"]: item for item in items_data}
        ip_addresses = list(unique_items.keys())
        existing_records = {
            record.ip_address: record
            for record in IpMetadata.objects.filter(ip_address__in=ip_addresses)
        }

        to_create = []
        to_update = []

        for ip_address, item in unique_items.items():
            name = item.get("name", "")
            asset_kind = item.get("asset_kind", IpMetadata.KIND_UNKNOWN)
            instance_id = item.get("instance_id", "")
            interface_id = item.get("interface_id", "")
            instance_type = item.get("instance_type", "")
            state = item.get("state", "")
            region = item.get("region", "")
            availability_zone = item.get("availability_zone", "")
            account_owner = item.get("account_owner", "")
            provider = item.get("provider", "")
            tags = item.get("tags", {})
            attributes = item.get("attributes", {})

            if ip_address in existing_records:
                record = existing_records[ip_address]
                record.name = name
                record.asset_kind = asset_kind
                record.instance_id = instance_id
                record.interface_id = interface_id
                record.instance_type = instance_type
                record.state = state
                record.region = region
                record.availability_zone = availability_zone
                record.account_owner = account_owner
                record.provider = provider
                record.tags = tags
                record.attributes = attributes
                to_update.append(record)
            else:
                to_create.append(IpMetadata(
                    ip_address=ip_address,
                    name=name,
                    asset_kind=asset_kind,
                    instance_id=instance_id,
                    interface_id=interface_id,
                    instance_type=instance_type,
                    state=state,
                    region=region,
                    availability_zone=availability_zone,
                    account_owner=account_owner,
                    provider=provider,
                    tags=tags,
                    attributes=attributes,
                ))

        if to_create:
            IpMetadata.objects.bulk_create(to_create, batch_size=1000)
            created = len(to_create)

        if to_update:
            IpMetadata.objects.bulk_update(
                to_update,
                fields=[
                    "name",
                    "asset_kind",
                    "instance_id",
                    "interface_id",
                    "instance_type",
                    "state",
                    "region",
                    "availability_zone",
                    "account_owner",
                    "provider",
                    "tags",
                    "attributes",
                ],
                batch_size=1000
            )
            updated = len(to_update)

        return Response({"created": created, "updated": updated})


class NetworkGroupImportView(APIView):
    def post(self, request):
        serializer = NetworkGroupImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        items_data = serializer.validated_data["items"]
        if not items_data:
            return Response({"created": 0, "updated": 0})

        unique_items = {item["name"]: item for item in items_data}
        names = list(unique_items.keys())
        existing_records = {
            record.name: record
            for record in NetworkGroup.objects.filter(name__in=names)
        }

        to_create = []
        to_update = []
        errors = {}

        for name, item in unique_items.items():
            cidr_values = item.get("cidrs") or []
            cidr = item.get("cidr", "").strip()
            if cidr:
                cidr_values = [cidr, *cidr_values]

            payload = {
                "name": name,
                "kind": item.get("kind", NetworkGroup.KIND_CUSTOM),
                "cidrs": cidr_values,
                "tags": item.get("tags", []),
                "description": item.get("description", ""),
            }

            record = existing_records.get(name)
            item_serializer = NetworkGroupSerializer(
                instance=record,
                data=payload,
                partial=record is not None,
            )
            if not item_serializer.is_valid():
                errors[name] = item_serializer.errors
                continue

            normalized = item_serializer.validated_data
            if record is not None:
                record.kind = normalized.get("kind", record.kind)
                record.cidr = normalized.get("cidr", record.cidr)
                record.cidrs = normalized.get("cidrs", record.cidrs)
                record.tags = normalized.get("tags", record.tags)
                record.description = normalized.get("description", record.description)
                to_update.append(record)
            else:
                to_create.append(NetworkGroup(**normalized))

        if errors:
            return Response(
                {"created": 0, "updated": 0, "errors": errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            with transaction.atomic():
                if to_create:
                    NetworkGroup.objects.bulk_create(to_create, batch_size=1000)
                if to_update:
                    NetworkGroup.objects.bulk_update(
                        to_update,
                        fields=["kind", "cidrs", "cidr", "tags", "description"],
                        batch_size=1000,
                    )
        except IntegrityError as exc:
            return Response(
                {
                    "detail": "Failed to import one or more groups due to conflicting names. Refresh and retry.",
                    "error": str(exc),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({"created": len(to_create), "updated": len(to_update)})


class FlowLogImportListView(APIView):
    def get(self, request):
        grouped = (
            FlowLogEntry.objects.values("source")
            .annotate(
                entry_count=Count("id"),
                first_seen=Min("start_time"),
                last_seen=Max("end_time"),
                last_ingested_at=Max("ingested_at"),
            )
            .order_by("-last_ingested_at", "source")
        )

        results = []
        for row in grouped:
            source = (row.get("source") or "").strip()
            results.append(
                {
                    "source": source,
                    "label": source or "(unspecified)",
                    "entry_count": row["entry_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "last_ingested_at": row["last_ingested_at"],
                }
            )

        return Response({"count": len(results), "results": results})


class FlowLogPurgeView(APIView):
    def post(self, request):
        source = request.data.get("source", None)
        if source is not None and not isinstance(source, str):
            return Response(
                {"detail": "`source` must be a string when provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if isinstance(source, str):
            source = source.strip()

        if source is None:
            deleted_flow_logs, _ = FlowLogEntry.objects.all().delete()
            deleted_correlated_flows, _ = CorrelatedFlow.objects.all().delete()
            rebuild = {"created": 0, "updated": 0, "processed": 0}
            return Response(
                {
                    "scope": "all",
                    "source": None,
                    "deleted_flow_logs": deleted_flow_logs,
                    "deleted_correlated_flows": deleted_correlated_flows,
                    "remaining_flow_logs": FlowLogEntry.objects.count(),
                    "remaining_correlated_flows": CorrelatedFlow.objects.count(),
                    "rebuild": rebuild,
                }
            )

        deleted_flow_logs, _ = FlowLogEntry.objects.filter(source=source).delete()
        rebuild = {"created": 0, "updated": 0, "processed": 0}
        if deleted_flow_logs > 0:
            rebuild = rebuild_correlated_flows(batch_size=2000)
        return Response(
            {
                "scope": "source",
                "source": source,
                "deleted_flow_logs": deleted_flow_logs,
                "remaining_flow_logs": FlowLogEntry.objects.count(),
                "remaining_correlated_flows": CorrelatedFlow.objects.count(),
                "rebuild": rebuild,
            }
        )


class NetworkGroupPurgeView(APIView):
    def post(self, request):
        deleted_network_groups, _ = NetworkGroup.objects.all().delete()
        return Response(
            {
                "deleted_network_groups": deleted_network_groups,
                "remaining_network_groups": NetworkGroup.objects.count(),
            }
        )


class MeshGraphView(APIView):
    def get(self, request):
        queryset = CorrelatedFlow.objects.order_by("-last_seen").only(
            "client_ip",
            "server_ip",
            "protocol",
            "server_port",
            "flow_count",
            "c2s_packets",
            "c2s_bytes",
            "s2c_packets",
            "s2c_bytes",
            "last_seen",
        )

        edge_limit = None
        limit = request.query_params.get("limit")
        if limit:
            parsed_limit = _safe_int(limit, default=300, minimum=1, maximum=5000)
            if parsed_limit > 0:
                edge_limit = parsed_limit

        payload = build_mesh_payload(queryset, edge_limit=edge_limit)
        if edge_limit is not None:
            connected_node_ids = {
                edge["source"]
                for edge in payload["edges"]
                if edge.get("source")
            } | {
                edge["target"]
                for edge in payload["edges"]
                if edge.get("target")
            }
            all_nodes = payload["nodes"]
            connected_nodes = [
                node
                for node in all_nodes
                if node.get("id") in connected_node_ids
            ]
            connected_ids = {node.get("id") for node in connected_nodes if node.get("id")}

            # Preserve at least one representative node per group even when
            # its traffic edges are outside the current edge limit.
            best_group_node: dict[str, dict] = {}
            for node in all_nodes:
                group_name = str(node.get("group") or "").strip()
                node_id = node.get("id")
                if not group_name or not node_id or node_id in connected_ids:
                    continue
                current = best_group_node.get(group_name)
                node_traffic = (node.get("bytes_in", 0) or 0) + (node.get("bytes_out", 0) or 0)
                if current is None:
                    best_group_node[group_name] = node
                    continue
                current_traffic = (current.get("bytes_in", 0) or 0) + (current.get("bytes_out", 0) or 0)
                if node_traffic > current_traffic:
                    best_group_node[group_name] = node

            payload["nodes"] = [*connected_nodes, *best_group_node.values()]
            payload["nodes"].sort(
                key=lambda item: item.get("bytes_in", 0) + item.get("bytes_out", 0),
                reverse=True,
            )

        return Response(payload)


class FirewallRecommendationView(APIView):
    def get(self, request):
        min_bytes = request.query_params.get("min_bytes", "0")
        try:
            threshold = int(min_bytes)
        except ValueError:
            threshold = 0

        recommendations = build_firewall_recommendations(
            CorrelatedFlow.objects.order_by("-last_seen").only(
                "client_ip",
                "server_ip",
                "protocol",
                "server_port",
                "flow_count",
                "c2s_packets",
                "c2s_bytes",
                "s2c_packets",
                "s2c_bytes",
                "first_seen",
                "last_seen",
            ),
            min_bytes=threshold,
        )

        return Response({"count": len(recommendations), "results": recommendations})
