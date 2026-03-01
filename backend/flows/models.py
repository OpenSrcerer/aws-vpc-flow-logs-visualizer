import ipaddress

from django.core.exceptions import ValidationError
from django.db import models


class FlowLogEntry(models.Model):
    version = models.PositiveSmallIntegerField(default=2)
    account_id = models.CharField(max_length=32, blank=True)
    interface_id = models.CharField(max_length=32, blank=True)
    srcaddr = models.GenericIPAddressField(db_index=True)
    dstaddr = models.GenericIPAddressField(db_index=True)
    srcport = models.PositiveIntegerField(null=True, blank=True)
    dstport = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.PositiveSmallIntegerField(db_index=True)
    packets = models.PositiveBigIntegerField(default=0)
    bytes = models.PositiveBigIntegerField(default=0)
    start_time = models.DateTimeField(db_index=True)
    end_time = models.DateTimeField(db_index=True)
    action = models.CharField(max_length=16, db_index=True)
    log_status = models.CharField(max_length=32, blank=True)
    source = models.CharField(max_length=128, blank=True)
    raw_line = models.TextField(blank=True)
    ingested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["srcaddr", "dstaddr", "protocol"]),
            models.Index(fields=["start_time", "end_time"]),
        ]

    def __str__(self) -> str:
        return f"{self.srcaddr}:{self.srcport} -> {self.dstaddr}:{self.dstport} ({self.protocol})"


class CorrelatedFlow(models.Model):
    canonical_key = models.CharField(max_length=255, unique=True)
    client_ip = models.GenericIPAddressField(db_index=True)
    server_ip = models.GenericIPAddressField(db_index=True)
    client_port = models.PositiveIntegerField(null=True, blank=True)
    server_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.PositiveSmallIntegerField(db_index=True)
    flow_count = models.PositiveIntegerField(default=0)
    c2s_packets = models.PositiveBigIntegerField(default=0)
    c2s_bytes = models.PositiveBigIntegerField(default=0)
    s2c_packets = models.PositiveBigIntegerField(default=0)
    s2c_bytes = models.PositiveBigIntegerField(default=0)
    first_seen = models.DateTimeField(db_index=True)
    last_seen = models.DateTimeField(db_index=True)
    action_counts = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["client_ip", "server_ip", "protocol"]),
            models.Index(fields=["last_seen"]),
        ]

    def __str__(self) -> str:
        return self.canonical_key


class IpMetadata(models.Model):
    KIND_INSTANCE = "INSTANCE"
    KIND_ENI = "ENI"
    KIND_ON_PREM = "ON_PREM"
    KIND_UNKNOWN = "UNKNOWN"

    KIND_CHOICES = [
        (KIND_INSTANCE, "Instance"),
        (KIND_ENI, "ENI"),
        (KIND_ON_PREM, "On-Prem"),
        (KIND_UNKNOWN, "Unknown"),
    ]

    ip_address = models.GenericIPAddressField(unique=True)
    name = models.CharField(max_length=128, blank=True)
    asset_kind = models.CharField(
        max_length=16,
        choices=KIND_CHOICES,
        default=KIND_UNKNOWN,
        db_index=True,
    )
    instance_id = models.CharField(max_length=64, blank=True, db_index=True)
    interface_id = models.CharField(max_length=32, blank=True, db_index=True)
    instance_type = models.CharField(max_length=64, blank=True)
    state = models.CharField(max_length=32, blank=True)
    region = models.CharField(max_length=32, blank=True)
    availability_zone = models.CharField(max_length=32, blank=True)
    account_owner = models.CharField(max_length=128, blank=True)
    provider = models.CharField(max_length=128, blank=True)
    tags = models.JSONField(default=list, blank=True)
    attributes = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name or self.ip_address


class NetworkGroup(models.Model):
    KIND_VPC = "VPC"
    KIND_CONTAINER = "CONTAINER"
    KIND_EXTERNAL = "EXTERNAL"
    KIND_CUSTOM = "CUSTOM"

    KIND_CHOICES = [
        (KIND_VPC, "VPC"),
        (KIND_CONTAINER, "Container"),
        (KIND_EXTERNAL, "External"),
        (KIND_CUSTOM, "Custom"),
    ]

    name = models.CharField(max_length=128, unique=True)
    cidr = models.CharField(max_length=64, blank=True, default="")
    cidrs = models.JSONField(default=list, blank=True)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES, default=KIND_CUSTOM)
    tags = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    @property
    def cidr_values(self) -> list[str]:
        if isinstance(self.cidrs, list) and self.cidrs:
            return [str(value).strip() for value in self.cidrs if str(value).strip()]
        return [self.cidr] if self.cidr else []

    def clean(self) -> None:
        raw_values: list[str] = []
        if self.cidr:
            raw_values.append(str(self.cidr).strip())

        if isinstance(self.cidrs, list):
            raw_values.extend(self.cidrs)
        elif self.cidrs:
            raise ValidationError({"cidrs": "CIDRs must be provided as a list of CIDR strings."})

        normalized: list[str] = []
        seen: set[str] = set()
        errors: list[str] = []

        for raw_value in raw_values:
            value = str(raw_value).strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                errors.append(f"{value}: {exc}")
                continue

            network_text = str(network)
            if network_text not in seen:
                seen.add(network_text)
                normalized.append(network_text)

        if errors:
            raise ValidationError({"cidrs": errors})

        if not normalized:
            raise ValidationError({"cidrs": "At least one CIDR is required."})

        self.cidrs = normalized
        self.cidr = normalized[0]

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        cidrs = self.cidr_values
        if len(cidrs) == 1:
            return f"{self.name} ({cidrs[0]})"
        return f"{self.name} ({len(cidrs)} CIDRs)"
