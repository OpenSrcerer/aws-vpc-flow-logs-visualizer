import ipaddress

from rest_framework import serializers

from .models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup
from .parsers import parse_vpc_flow_log_format


class FlowLogEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = FlowLogEntry
        fields = "__all__"


class CorrelatedFlowSerializer(serializers.ModelSerializer):
    total_bytes = serializers.SerializerMethodField()
    total_packets = serializers.SerializerMethodField()

    class Meta:
        model = CorrelatedFlow
        fields = "__all__"

    def get_total_bytes(self, obj: CorrelatedFlow) -> int:
        return obj.c2s_bytes + obj.s2c_bytes

    def get_total_packets(self, obj: CorrelatedFlow) -> int:
        return obj.c2s_packets + obj.s2c_packets


def _normalize_tag_map(value) -> dict[str, str]:
    if value in (None, ""):
        return {}

    normalized: dict[str, str] = {}

    def add_tag(key, tag_value=""):
        key_text = str(key).strip()
        if not key_text:
            return
        value_text = "" if tag_value is None else str(tag_value).strip()
        normalized[key_text] = value_text

    if isinstance(value, dict):
        for key, tag_value in value.items():
            add_tag(key, tag_value)
        return normalized

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                for key, tag_value in item.items():
                    add_tag(key, tag_value)
                continue

            text = str(item).strip()
            if not text:
                continue
            if "=" in text:
                key, tag_value = text.split("=", 1)
                add_tag(key, tag_value)
            else:
                add_tag(text, "")
        return normalized

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        if "=" in text:
            key, tag_value = text.split("=", 1)
            add_tag(key, tag_value)
        else:
            add_tag(text, "")
        return normalized

    raise serializers.ValidationError("Tags must be a map of key/value pairs.")


class IpMetadataSerializer(serializers.ModelSerializer):
    tags = serializers.JSONField(required=False)
    attributes = serializers.DictField(required=False)

    class Meta:
        model = IpMetadata
        fields = "__all__"

    def validate_tags(self, value):
        return _normalize_tag_map(value)

    def to_representation(self, instance):
        payload = super().to_representation(instance)
        payload["tags"] = _normalize_tag_map(payload.get("tags"))
        return payload


class NetworkGroupSerializer(serializers.ModelSerializer):
    cidrs = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=False,
    )

    class Meta:
        model = NetworkGroup
        fields = "__all__"

    @staticmethod
    def _normalize_cidr(value: str) -> str:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate_cidr(self, value: str) -> str:
        value = value.strip()
        if not value:
            raise serializers.ValidationError("This field may not be blank.")
        return self._normalize_cidr(value)

    def validate_cidrs(self, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_value in value:
            cidr = self._normalize_cidr(str(raw_value).strip())
            if cidr in seen:
                continue
            seen.add(cidr)
            normalized.append(cidr)
        if not normalized:
            raise serializers.ValidationError("Provide at least one CIDR.")
        return normalized

    def validate(self, attrs: dict) -> dict:
        has_cidr = "cidr" in attrs
        has_cidrs = "cidrs" in attrs

        if has_cidrs:
            cidrs = attrs["cidrs"]
            if has_cidr and attrs.get("cidr"):
                primary = attrs["cidr"]
                if primary in cidrs:
                    cidrs = [primary] + [item for item in cidrs if item != primary]
                else:
                    cidrs = [primary, *cidrs]
            attrs["cidrs"] = cidrs
            attrs["cidr"] = cidrs[0]
            return attrs

        if has_cidr:
            attrs["cidrs"] = [attrs["cidr"]]
            return attrs

        if self.instance is None:
            raise serializers.ValidationError({"cidrs": "Provide `cidrs` or `cidr`."})

        return attrs


class FlowLogUploadSerializer(serializers.Serializer):
    file = serializers.FileField(required=False)
    files = serializers.ListField(child=serializers.FileField(), required=False, allow_empty=False)
    lines = serializers.CharField(required=False, allow_blank=True)
    source = serializers.CharField(required=False, allow_blank=True, max_length=128)
    auto_correlate = serializers.BooleanField(required=False, default=True)
    log_format = serializers.CharField(required=False, allow_blank=True, max_length=2048)

    def validate_log_format(self, value):
        try:
            return parse_vpc_flow_log_format(value)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate(self, attrs):
        has_file = bool(attrs.get("file"))
        has_files = bool(attrs.get("files"))
        has_lines = bool(attrs.get("lines"))

        if not has_file and not has_files and not has_lines:
            raise serializers.ValidationError("Provide `file`, `files`, or `lines`.")
        return attrs


class IpMetadataImportItemSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField()
    name = serializers.CharField(required=False, allow_blank=True, max_length=128)
    asset_kind = serializers.ChoiceField(
        choices=IpMetadata.KIND_CHOICES,
        required=False,
        default=IpMetadata.KIND_UNKNOWN,
    )
    instance_id = serializers.CharField(required=False, allow_blank=True, max_length=64)
    interface_id = serializers.CharField(required=False, allow_blank=True, max_length=32)
    instance_type = serializers.CharField(required=False, allow_blank=True, max_length=64)
    state = serializers.CharField(required=False, allow_blank=True, max_length=32)
    region = serializers.CharField(required=False, allow_blank=True, max_length=32)
    availability_zone = serializers.CharField(required=False, allow_blank=True, max_length=32)
    account_owner = serializers.CharField(required=False, allow_blank=True, max_length=128)
    provider = serializers.CharField(required=False, allow_blank=True, max_length=128)
    tags = serializers.JSONField(required=False)
    attributes = serializers.DictField(required=False)

    def validate_tags(self, value):
        return _normalize_tag_map(value)


class IpMetadataImportSerializer(serializers.Serializer):
    items = IpMetadataImportItemSerializer(many=True)


class NetworkGroupImportItemSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=128)
    kind = serializers.ChoiceField(
        choices=NetworkGroup.KIND_CHOICES,
        required=False,
        default=NetworkGroup.KIND_CUSTOM,
    )
    cidr = serializers.CharField(required=False, allow_blank=True, max_length=64)
    cidrs = serializers.ListField(
        child=serializers.CharField(allow_blank=True),
        required=False,
    )
    tags = serializers.ListField(child=serializers.CharField(), required=False)
    description = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        raw_cidrs = attrs.get("cidrs") or []
        cidrs = [str(value).strip() for value in raw_cidrs if str(value).strip()]
        if "cidrs" in attrs:
            attrs["cidrs"] = cidrs

        cidr = attrs.get("cidr", "").strip()
        attrs["cidr"] = cidr

        if not cidrs and not cidr:
            raise serializers.ValidationError("Provide `cidrs` or `cidr`.")
        return attrs


class NetworkGroupImportSerializer(serializers.Serializer):
    items = NetworkGroupImportItemSerializer(many=True)
