import gzip

from django.db import IntegrityError, transaction
from django.db.models import Count, F, Max, Min, Q
from django.utils.dateparse import parse_datetime
from rest_framework import status, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from .advanced_filters import (
    AdvancedFilterError,
    evaluate_advanced_filter,
    inject_instance_context,
    parse_advanced_filter,
    validate_advanced_filter_ast,
)
from .models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup
from .parsers import parse_vpc_flow_log_lines
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

        protocol_alias_map = {"icmp": 1, "tcp": 6, "udp": 17}
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

            ip_addresses: set[str] = set()
            for src_ip, dst_ip in queryset.values_list("srcaddr", "dstaddr").iterator(chunk_size=2000):
                if src_ip:
                    ip_addresses.add(str(src_ip))
                if dst_ip:
                    ip_addresses.add(str(dst_ip))

            metadata_by_ip: dict[str, dict] = {}
            if ip_addresses:
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
                metadata_rows = IpMetadata.objects.filter(ip_address__in=ip_addresses).values(*metadata_fields)
                for metadata_row in metadata_rows.iterator(chunk_size=2000):
                    metadata_by_ip[str(metadata_row["ip_address"])] = metadata_row

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

            matching_ids = []
            for row in candidate_rows.iterator(chunk_size=2000):
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
            queryset = queryset.filter(id__in=matching_ids)

        return queryset


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


def _decode_uploaded_flow_file(uploaded_file) -> str:
    file_name = (getattr(uploaded_file, "name", "") or "").lower()
    payload = uploaded_file.read()

    # Accept gzip uploads (.log.gz/.gz) and auto-detect via magic bytes.
    is_gzip = file_name.endswith(".gz") or payload.startswith(b"\x1f\x8b")
    if is_gzip:
        try:
            payload = gzip.decompress(payload)
        except (OSError, EOFError) as exc:
            raise ValueError("Uploaded gzip file could not be decompressed.") from exc

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Uploaded flow log file is not valid UTF-8 text.") from exc


class FlowLogUploadView(APIView):
    def post(self, request):
        serializer = FlowLogUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        source = serializer.validated_data.get("source", "")
        auto_correlate = serializer.validated_data.get("auto_correlate", True)
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

        parse_errors: list[str] = []
        ingested_total = 0
        correlation_stats = {"created": 0, "updated": 0}
        file_results: list[dict] = []

        for uploaded in uploaded_files:
            try:
                raw = _decode_uploaded_flow_file(uploaded)
            except ValueError as exc:
                parse_errors.append(f"{uploaded.name}: {exc}")
                file_results.append(
                    {
                        "name": uploaded.name,
                        "ingested": 0,
                        "parse_error_count": 1,
                    }
                )
                continue

            records, errors = parse_vpc_flow_log_lines(raw.splitlines())
            entries = parsed_records_to_entries(records, source=source)

            if entries:
                FlowLogEntry.objects.bulk_create(entries, batch_size=1000)
                ingested_total += len(entries)

                if auto_correlate:
                    stats = upsert_correlated_flows(entries)
                    correlation_stats["created"] += stats.get("created", 0)
                    correlation_stats["updated"] += stats.get("updated", 0)

            parse_errors.extend([f"{uploaded.name}: {item}" for item in errors])
            file_results.append(
                {
                    "name": uploaded.name,
                    "ingested": len(entries),
                    "parse_error_count": len(errors),
                }
            )

        lines_payload = serializer.validated_data.get("lines", "")
        if lines_payload:
            records, errors = parse_vpc_flow_log_lines(lines_payload.splitlines())
            entries = parsed_records_to_entries(records, source=source)

            if entries:
                FlowLogEntry.objects.bulk_create(entries, batch_size=1000)
                ingested_total += len(entries)
                if auto_correlate:
                    stats = upsert_correlated_flows(entries)
                    correlation_stats["created"] += stats.get("created", 0)
                    correlation_stats["updated"] += stats.get("updated", 0)

            parse_errors.extend(errors)
            file_results.append(
                {
                    "name": "(pasted-lines)",
                    "ingested": len(entries),
                    "parse_error_count": len(errors),
                }
            )

        return Response(
            {
                "ingested": ingested_total,
                "ingested_files": len(file_results),
                "file_results": file_results,
                "parse_errors": parse_errors[:100],
                "parse_error_count": len(parse_errors),
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
        queryset = CorrelatedFlow.objects.order_by("-last_seen")

        edge_limit = None
        limit = request.query_params.get("limit")
        if limit:
            try:
                parsed_limit = int(limit)
                if parsed_limit > 0:
                    edge_limit = parsed_limit
            except ValueError:
                pass

        payload = build_mesh_payload(queryset)
        if edge_limit is not None:
            limited_edges = payload["edges"][:edge_limit]
            connected_node_ids = {
                edge["source"]
                for edge in limited_edges
                if edge.get("source")
            } | {
                edge["target"]
                for edge in limited_edges
                if edge.get("target")
            }
            payload["edges"] = limited_edges
            payload["nodes"] = [
                node
                for node in payload["nodes"]
                if node.get("id") in connected_node_ids
            ]

        return Response(payload)


class FirewallRecommendationView(APIView):
    def get(self, request):
        min_bytes = request.query_params.get("min_bytes", "0")
        try:
            threshold = int(min_bytes)
        except ValueError:
            threshold = 0

        recommendations = build_firewall_recommendations(
            CorrelatedFlow.objects.order_by("-last_seen"),
            min_bytes=threshold,
        )

        return Response({"count": len(recommendations), "results": recommendations})
