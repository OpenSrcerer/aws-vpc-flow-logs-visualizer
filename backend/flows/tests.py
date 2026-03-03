import base64
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone as django_timezone
from rest_framework.test import APITestCase
from flows.parsers import parse_vpc_flow_log_format, parse_vpc_flow_log_line, ParsedFlowRecord


def _basic_auth(username: str, password: str) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"HTTP_AUTHORIZATION": f"Basic {token}"}

class ParseVPCFlowLogLineTests(TestCase):
    def test_parse_valid_line(self):
        line = "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"
        record = parse_vpc_flow_log_line(line)
        self.assertEqual(record.version, 2)
        self.assertEqual(record.account_id, "123456789010")
        self.assertEqual(record.interface_id, "eni-1235b8ca123456789")
        self.assertEqual(record.srcaddr, "172.31.16.139")
        self.assertEqual(record.dstaddr, "172.31.16.21")
        self.assertEqual(record.srcport, 20641)
        self.assertEqual(record.dstport, 22)
        self.assertEqual(record.protocol, 6)
        self.assertEqual(record.packets, 20)
        self.assertEqual(record.bytes, 4249)
        self.assertEqual(record.start_time, datetime.fromtimestamp(1418530010, tz=timezone.utc))
        self.assertEqual(record.end_time, datetime.fromtimestamp(1418530070, tz=timezone.utc))
        self.assertEqual(record.action, "ACCEPT")
        self.assertEqual(record.log_status, "OK")
        self.assertEqual(record.raw_line, line)

    def test_parse_insufficient_fields(self):
        line = "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT"
        with self.assertRaisesMessage(ValueError, "Expected at least 14 fields for VPC flow log format"):
            parse_vpc_flow_log_line(line)

    def test_parse_missing_srcaddr_dstaddr(self):
        line1 = "2 123456789010 eni-1235b8ca123456789 - 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"
        with self.assertRaisesMessage(ValueError, "srcaddr and dstaddr are required"):
            parse_vpc_flow_log_line(line1)

        line2 = "2 123456789010 eni-1235b8ca123456789 172.31.16.139 - 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"
        with self.assertRaisesMessage(ValueError, "srcaddr and dstaddr are required"):
            parse_vpc_flow_log_line(line2)

    def test_parse_defaults(self):
        # Using '-' for version, ports, protocol, packets, bytes, start, end
        line = "- 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 - - - - - - - ACCEPT OK"
        record = parse_vpc_flow_log_line(line)
        self.assertEqual(record.version, 2)
        self.assertEqual(record.account_id, "123456789010")
        self.assertEqual(record.interface_id, "eni-1235b8ca123456789")
        self.assertEqual(record.srcaddr, "172.31.16.139")
        self.assertEqual(record.dstaddr, "172.31.16.21")
        self.assertIsNone(record.srcport)
        self.assertIsNone(record.dstport)
        self.assertEqual(record.protocol, 0)
        self.assertEqual(record.packets, 0)
        self.assertEqual(record.bytes, 0)
        self.assertEqual(record.start_time, datetime.fromtimestamp(0, tz=timezone.utc))
        self.assertEqual(record.end_time, datetime.fromtimestamp(0, tz=timezone.utc))
        self.assertEqual(record.action, "ACCEPT")
        self.assertEqual(record.log_status, "OK")
        self.assertEqual(record.raw_line, line)

    def test_parse_custom_format_with_field_reordering(self):
        log_format = (
            "${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} "
            "${start} ${end} ${action} ${log-status} ${version} ${account-id} ${interface-id}"
        )
        line = "172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK 2 123456789010 eni-1235"
        record = parse_vpc_flow_log_line(line, log_format=log_format)
        self.assertEqual(record.version, 2)
        self.assertEqual(record.account_id, "123456789010")
        self.assertEqual(record.interface_id, "eni-1235")
        self.assertEqual(record.srcaddr, "172.31.16.139")
        self.assertEqual(record.dstaddr, "172.31.16.21")
        self.assertEqual(record.srcport, 20641)
        self.assertEqual(record.dstport, 22)

    def test_parse_vpc_flow_log_format_requires_supported_fields(self):
        with self.assertRaisesMessage(
            ValueError,
            "log_format must include required fields",
        ):
            parse_vpc_flow_log_format("srcaddr dstaddr srcport dstport protocol packets bytes start end action")
from django.test import TestCase
from django.core.exceptions import ValidationError
from flows.models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup

class NetworkGroupCleanTests(TestCase):
    def test_valid_cidr(self):
        """Test that providing a single valid cidr populates cidrs list."""
        group = NetworkGroup(name="test", cidr="10.0.0.0/8")
        group.clean()
        self.assertEqual(group.cidr, "10.0.0.0/8")
        self.assertEqual(group.cidrs, ["10.0.0.0/8"])

    def test_valid_cidrs_list(self):
        """Test that providing a list of cidrs populates cidr string."""
        group = NetworkGroup(name="test", cidrs=["192.168.1.0/24", "10.0.0.0/8"])
        group.clean()
        self.assertEqual(group.cidr, "192.168.1.0/24")
        self.assertEqual(group.cidrs, ["192.168.1.0/24", "10.0.0.0/8"])

    def test_cidr_and_cidrs_combined(self):
        """Test combining cidr and cidrs fields."""
        group = NetworkGroup(name="test", cidr="10.0.0.0/8", cidrs=["192.168.1.0/24"])
        group.clean()
        self.assertEqual(group.cidrs, ["10.0.0.0/8", "192.168.1.0/24"])
        self.assertEqual(group.cidr, "10.0.0.0/8")

    def test_invalid_cidrs_type(self):
        """Test that cidrs must be a list if provided."""
        group = NetworkGroup(name="test", cidrs="10.0.0.0/8")
        with self.assertRaises(ValidationError) as cm:
            group.clean()
        self.assertEqual(
            cm.exception.message_dict["cidrs"],
            ["CIDRs must be provided as a list of CIDR strings."]
        )

    def test_invalid_cidr_string(self):
        """Test that invalid CIDR strings raise ValidationError."""
        group = NetworkGroup(name="test", cidrs=["invalid-cidr"])
        with self.assertRaises(ValidationError) as cm:
            group.clean()
        self.assertTrue(
            any("invalid-cidr" in msg for msg in cm.exception.message_dict["cidrs"])
        )

    def test_multiple_invalid_cidr_strings(self):
        """Test that multiple invalid CIDR strings return all errors."""
        group = NetworkGroup(name="test", cidrs=["invalid1", "invalid2"])
        with self.assertRaises(ValidationError) as cm:
            group.clean()
        messages = cm.exception.message_dict["cidrs"]
        self.assertEqual(len(messages), 2)
        self.assertTrue(any("invalid1" in msg for msg in messages))
        self.assertTrue(any("invalid2" in msg for msg in messages))

    def test_no_cidr_provided(self):
        """Test that at least one CIDR must be provided."""
        group = NetworkGroup(name="test")
        with self.assertRaises(ValidationError) as cm:
            group.clean()
        self.assertEqual(
            cm.exception.message_dict["cidrs"],
            ["At least one CIDR is required."]
        )

    def test_empty_cidr_strings_ignored(self):
        """Test that empty string values are ignored."""
        group = NetworkGroup(name="test", cidr="", cidrs=["", "   ", "10.0.0.0/8"])
        group.clean()
        self.assertEqual(group.cidrs, ["10.0.0.0/8"])
        self.assertEqual(group.cidr, "10.0.0.0/8")

    def test_duplicate_cidrs_removed(self):
        """Test that duplicate CIDR entries are removed."""
        group = NetworkGroup(name="test", cidr="10.0.0.0/8", cidrs=["10.0.0.0/8", "192.168.1.0/24", "10.0.0.0/8"])
        group.clean()
        self.assertEqual(group.cidrs, ["10.0.0.0/8", "192.168.1.0/24"])

    def test_strict_false_normalization(self):
        """Test that CIDR normalization ignores host bits (strict=False)."""
        group = NetworkGroup(name="test", cidr="192.168.1.5/24")
        group.clean()
        self.assertEqual(group.cidr, "192.168.1.0/24")
        self.assertEqual(group.cidrs, ["192.168.1.0/24"])

    def test_ipv6_normalization(self):
        """Test that IPv6 addresses work and are normalized."""
        group = NetworkGroup(name="test", cidr="2001:db8::1/64")
        group.clean()
        self.assertEqual(group.cidr, "2001:db8::/64")
        self.assertEqual(group.cidrs, ["2001:db8::/64"])
from flows.parsers import parse_vpc_flow_log_lines

class ParseVPCFlowLogLinesTest(TestCase):
    def test_happy_path(self):
        lines = [
            "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
            "2 123456789010 eni-1235b8ca123456789 172.31.16.21 172.31.16.139 22 20641 6 19 5288 1418530010 1418530070 ACCEPT OK",
        ]
        parsed, errors = parse_vpc_flow_log_lines(lines)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(parsed), 2)

        self.assertIsInstance(parsed[0], ParsedFlowRecord)
        self.assertEqual(parsed[0].srcaddr, "172.31.16.139")
        self.assertEqual(parsed[0].dstaddr, "172.31.16.21")
        self.assertEqual(parsed[0].srcport, 20641)
        self.assertEqual(parsed[0].dstport, 22)
        self.assertEqual(parsed[0].protocol, 6)
        self.assertEqual(parsed[0].action, "ACCEPT")
        self.assertEqual(parsed[0].log_status, "OK")

        self.assertIsInstance(parsed[1], ParsedFlowRecord)
        self.assertEqual(parsed[1].srcaddr, "172.31.16.21")
        self.assertEqual(parsed[1].dstaddr, "172.31.16.139")

    def test_empty_and_comment_lines(self):
        lines = [
            "# This is a comment",
            "",
            "   ",
            "# Another comment",
        ]
        parsed, errors = parse_vpc_flow_log_lines(lines)
        self.assertEqual(len(parsed), 0)
        self.assertEqual(len(errors), 0)

    def test_invalid_lines(self):
        lines = [
            "2 123456789010", # Too few fields
            "2 123456789010 eni-1235b8ca123456789 - - 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK", # Missing src/dst
            "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 BADPORT 22 6 20 4249 1418530010 1418530070 ACCEPT OK", # Invalid type
        ]
        parsed, errors = parse_vpc_flow_log_lines(lines)
        self.assertEqual(len(parsed), 0)
        self.assertEqual(len(errors), 3)

        self.assertEqual(errors[0]["line"], 1)
        self.assertIn("Expected at least 14 fields", errors[0]["error"])
        self.assertEqual(errors[0]["raw"], "2 123456789010")

        self.assertEqual(errors[1]["line"], 2)
        self.assertIn("srcaddr and dstaddr are required", errors[1]["error"])

        self.assertEqual(errors[2]["line"], 3)
        self.assertIn("invalid literal for int()", errors[2]["error"])

    def test_mixed_lines(self):
        lines = [
            "# Header",
            "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
            "",
            "2 123456789010", # Invalid
            "2 123456789010 eni-1235b8ca123456789 172.31.16.21 172.31.16.139 22 20641 6 19 5288 1418530010 1418530070 ACCEPT OK",
        ]
        parsed, errors = parse_vpc_flow_log_lines(lines)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(len(errors), 1)

        self.assertEqual(errors[0]["line"], 4)
        self.assertIn("Expected at least 14 fields", errors[0]["error"])


class FlowLogUploadApiTests(APITestCase):
    def test_upload_accepts_custom_log_format(self):
        response = self.client.post(
            "/api/uploads/flow-logs/",
            {
                "source": "custom-format-test",
                "lines": "172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK 2 123456789010 eni-1235",
                "log_format": (
                    "srcaddr dstaddr srcport dstport protocol packets bytes start end action "
                    "log-status version account-id interface-id"
                ),
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["ingested"], 1)
        self.assertEqual(response.data["parse_error_count"], 0)

        entry = FlowLogEntry.objects.get()
        self.assertEqual(entry.source, "custom-format-test")
        self.assertEqual(entry.srcaddr, "172.31.16.139")
        self.assertEqual(entry.dstaddr, "172.31.16.21")
        self.assertEqual(entry.srcport, 20641)
        self.assertEqual(entry.dstport, 22)
        self.assertEqual(entry.protocol, 6)
        self.assertEqual(entry.action, "ACCEPT")
        self.assertEqual(entry.log_status, "OK")

    def test_upload_rejects_invalid_log_format(self):
        response = self.client.post(
            "/api/uploads/flow-logs/",
            {
                "lines": "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
                "log_format": "version account-id interface-id dstaddr srcport dstport protocol packets bytes start end action log-status",
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("required fields", str(response.data.get("log_format", "")))


class MeshGroupingTests(APITestCase):
    def test_mesh_excludes_firewall_simulator_groups_from_node_grouping(self):
        now = django_timezone.now()

        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.10:51515>10.0.1.20:443/p6",
            client_ip="10.0.0.10",
            server_ip="10.0.1.20",
            client_port=51515,
            server_port=443,
            protocol=6,
            flow_count=1,
            c2s_packets=10,
            c2s_bytes=2048,
            s2c_packets=8,
            s2c_bytes=1024,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 1},
        )

        NetworkGroup.objects.create(
            name="prod-vpc",
            kind=NetworkGroup.KIND_VPC,
            cidrs=["10.0.0.0/24"],
            tags=[],
        )
        NetworkGroup.objects.create(
            name="sim-only-snapshot",
            kind=NetworkGroup.KIND_CUSTOM,
            cidrs=["10.0.1.0/24"],
            tags=["firewall-simulator"],
            description="snapshot\n[FIREWALL_SIM_SOURCE] {\"mode\":\"container\"}",
        )

        response = self.client.get("/api/mesh/?limit=10")

        self.assertEqual(response.status_code, 200)
        nodes_by_ip = {item["ip"]: item for item in response.data.get("nodes", [])}

        self.assertEqual(nodes_by_ip["10.0.0.10"]["group"], "prod-vpc")
        self.assertEqual(nodes_by_ip["10.0.1.20"]["group"], "")

    def test_mesh_limit_applies_after_edge_aggregation(self):
        now = django_timezone.now()

        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.10:51515>10.0.1.20:443/p6",
            client_ip="10.0.0.10",
            server_ip="10.0.1.20",
            client_port=51515,
            server_port=443,
            protocol=6,
            flow_count=50,
            c2s_packets=200,
            c2s_bytes=60000,
            s2c_packets=180,
            s2c_bytes=45000,
            first_seen=now,
            last_seen=now - timedelta(minutes=20),
            action_counts={"ACCEPT": 50},
        )
        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.10:52525>10.0.1.20:8443/p6",
            client_ip="10.0.0.10",
            server_ip="10.0.1.20",
            client_port=52525,
            server_port=8443,
            protocol=6,
            flow_count=2,
            c2s_packets=6,
            c2s_bytes=300,
            s2c_packets=4,
            s2c_bytes=220,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 2},
        )

        response = self.client.get("/api/mesh/?limit=1")

        self.assertEqual(response.status_code, 200)
        edges = response.data.get("edges", [])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["port"], 443)
        self.assertEqual(edges[0]["protocol"], 6)


class GlobalSearchTests(APITestCase):
    def test_global_search_returns_matches_across_models(self):
        now = django_timezone.now()

        FlowLogEntry.objects.create(
            version=2,
            account_id="123456789012",
            interface_id="eni-search1",
            srcaddr="10.0.0.10",
            dstaddr="10.0.0.11",
            srcport=51515,
            dstport=443,
            protocol=6,
            packets=10,
            bytes=2048,
            start_time=now,
            end_time=now,
            action="ACCEPT",
            log_status="OK",
            source="search-seed",
            raw_line="",
        )
        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.10:51515>10.0.0.11:443/p6",
            client_ip="10.0.0.10",
            server_ip="10.0.0.11",
            client_port=51515,
            server_port=443,
            protocol=6,
            flow_count=1,
            c2s_packets=10,
            c2s_bytes=2048,
            s2c_packets=8,
            s2c_bytes=1024,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 1},
        )
        IpMetadata.objects.create(
            ip_address="10.0.0.10",
            name="app-search-node",
            tags={"environment": "prod"},
        )
        NetworkGroup.objects.create(
            name="app-search-group",
            kind=NetworkGroup.KIND_CUSTOM,
            cidrs=["10.0.0.0/24"],
            tags=["searchable"],
        )

        response = self.client.get("/api/search/?q=search")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["query"], "search")
        self.assertGreaterEqual(response.data["counts"]["flow_logs"], 1)
        self.assertGreaterEqual(response.data["counts"]["ip_metadata"], 1)
        self.assertGreaterEqual(response.data["counts"]["network_groups"], 1)

    def test_global_search_matches_protocol_alias(self):
        now = django_timezone.now()
        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.20:50000>10.0.0.21:53/p17",
            client_ip="10.0.0.20",
            server_ip="10.0.0.21",
            client_port=50000,
            server_port=53,
            protocol=17,
            flow_count=1,
            c2s_packets=4,
            c2s_bytes=512,
            s2c_packets=4,
            s2c_bytes=512,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 1},
        )

        response = self.client.get("/api/search/?q=udp")

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.data["counts"]["correlated_flows"], 1)

    def test_global_search_matches_ipip_protocol_alias(self):
        now = django_timezone.now()
        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.30:0>10.0.0.31:0/p4",
            client_ip="10.0.0.30",
            server_ip="10.0.0.31",
            client_port=None,
            server_port=None,
            protocol=4,
            flow_count=1,
            c2s_packets=3,
            c2s_bytes=1024,
            s2c_packets=3,
            s2c_bytes=1024,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 1},
        )

        response = self.client.get("/api/search/?q=ipip")

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.data["counts"]["correlated_flows"], 1)


class FlowLogAdvancedFilterTests(APITestCase):
    def test_not_equal_includes_null_ports(self):
        now = django_timezone.now()

        keep_null = FlowLogEntry.objects.create(
            version=2,
            account_id="123456789012",
            interface_id="eni-null-port",
            srcaddr="10.0.0.10",
            dstaddr="10.0.0.11",
            srcport=50000,
            dstport=None,
            protocol=6,
            packets=5,
            bytes=500,
            start_time=now,
            end_time=now,
            action="ACCEPT",
            log_status="OK",
            source="filter-test",
            raw_line="",
        )
        keep_other_port = FlowLogEntry.objects.create(
            version=2,
            account_id="123456789012",
            interface_id="eni-other-port",
            srcaddr="10.0.0.12",
            dstaddr="10.0.0.13",
            srcport=50001,
            dstport=80,
            protocol=6,
            packets=6,
            bytes=600,
            start_time=now,
            end_time=now,
            action="ACCEPT",
            log_status="OK",
            source="filter-test",
            raw_line="",
        )
        FlowLogEntry.objects.create(
            version=2,
            account_id="123456789012",
            interface_id="eni-excluded-port",
            srcaddr="10.0.0.14",
            dstaddr="10.0.0.15",
            srcport=50002,
            dstport=443,
            protocol=6,
            packets=7,
            bytes=700,
            start_time=now,
            end_time=now,
            action="ACCEPT",
            log_status="OK",
            source="filter-test",
            raw_line="",
        )

        response = self.client.get("/api/flow-logs/?advanced_filter=dstport!=443&page_size=100")

        self.assertEqual(response.status_code, 200)
        returned_ids = {item["id"] for item in response.data["results"]}
        self.assertIn(keep_null.id, returned_ids)
        self.assertIn(keep_other_port.id, returned_ids)

    def test_cidr_filter_handles_large_result_set_in_sqlite(self):
        now = django_timezone.now()
        rows = []
        for i in range(1105):
            rows.append(
                FlowLogEntry(
                    version=2,
                    account_id="123456789012",
                    interface_id=f"eni-cidr-{i}",
                    srcaddr=f"10.108.{i // 256}.{i % 256}",
                    dstaddr="192.0.2.10",
                    srcport=40000 + (i % 1000),
                    dstport=443,
                    protocol=6,
                    packets=3,
                    bytes=300,
                    start_time=now,
                    end_time=now,
                    action="ACCEPT",
                    log_status="OK",
                    source="filter-test",
                    raw_line="",
                )
            )
        FlowLogEntry.objects.bulk_create(rows, batch_size=1000)

        response = self.client.get(
            "/api/flow-logs/?advanced_filter=addr.src==10.108.0.0/16&page_size=50&page=1"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1105)
        self.assertEqual(len(response.data["results"]), 50)

    def test_protocol_alias_ipip_matches_protocol_4(self):
        now = django_timezone.now()
        FlowLogEntry.objects.create(
            version=2,
            account_id="123456789012",
            interface_id="eni-ipip",
            srcaddr="10.200.0.10",
            dstaddr="10.200.0.11",
            srcport=None,
            dstport=None,
            protocol=4,
            packets=9,
            bytes=900,
            start_time=now,
            end_time=now,
            action="ACCEPT",
            log_status="OK",
            source="filter-test",
            raw_line="",
        )

        response = self.client.get("/api/flow-logs/?advanced_filter=protocol==ipip&page_size=50")

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.data["count"], 1)


class DashboardSummaryTests(APITestCase):
    def test_dashboard_summary_aggregates_traffic_and_protocols(self):
        now = django_timezone.now()

        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.10:51515>10.0.0.11:443/p6",
            client_ip="10.0.0.10",
            server_ip="10.0.0.11",
            client_port=51515,
            server_port=443,
            protocol=6,
            flow_count=4,
            c2s_packets=10,
            c2s_bytes=1000,
            s2c_packets=7,
            s2c_bytes=400,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 4},
        )
        CorrelatedFlow.objects.create(
            canonical_key="10.0.0.12:5353>10.0.0.53:53/p17",
            client_ip="10.0.0.12",
            server_ip="10.0.0.53",
            client_port=5353,
            server_port=53,
            protocol=17,
            flow_count=2,
            c2s_packets=3,
            c2s_bytes=300,
            s2c_packets=3,
            s2c_bytes=500,
            first_seen=now,
            last_seen=now,
            action_counts={"ACCEPT": 2},
        )

        response = self.client.get("/api/dashboard/summary/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["traffic"]["total_bytes"], 2200)
        self.assertEqual(response.data["traffic"]["total_packets"], 23)
        self.assertEqual(response.data["traffic"]["total_sessions"], 6)
        self.assertGreaterEqual(len(response.data["protocol_breakdown"]), 2)
        self.assertEqual(response.data["protocol_breakdown"][0]["protocol"], 6)
        self.assertEqual(response.data["protocol_breakdown"][0]["bytes"], 1400)


class EnvAccountAuthTests(APITestCase):
    @patch.dict(os.environ, {"WRITE_ACCOUNT": "admin:admin", "READ_ACCOUNT": "user:user"}, clear=False)
    def test_auth_enabled_requires_credentials(self):
        anonymous = self.client.get("/api/health/")
        self.assertEqual(anonymous.status_code, 401)

        read = self.client.get("/api/health/", **_basic_auth("user", "user"))
        self.assertEqual(read.status_code, 200)

    @patch.dict(os.environ, {"WRITE_ACCOUNT": "admin:admin", "READ_ACCOUNT": "user:user"}, clear=False)
    def test_read_account_is_read_only(self):
        response = self.client.post(
            "/api/maintenance/network-groups/purge/",
            {},
            format="json",
            **_basic_auth("user", "user"),
        )
        self.assertEqual(response.status_code, 403)

    @patch.dict(os.environ, {"WRITE_ACCOUNT": "admin:admin", "READ_ACCOUNT": "user:user"}, clear=False)
    def test_write_account_can_mutate(self):
        response = self.client.post(
            "/api/maintenance/network-groups/purge/",
            {},
            format="json",
            **_basic_auth("admin", "admin"),
        )
        self.assertEqual(response.status_code, 200)


class OpenApiDocsTests(APITestCase):
    def test_openapi_schema_endpoint(self):
        response = self.client.get("/api/schema/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("openapi", response.data)
        self.assertIn("paths", response.data)

    def test_swagger_ui_endpoint(self):
        response = self.client.get("/api/docs/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("swagger-ui", response.content.decode("utf-8").lower())

    def test_redoc_endpoint(self):
        response = self.client.get("/api/redoc/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("redoc", response.content.decode("utf-8").lower())
