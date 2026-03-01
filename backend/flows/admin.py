from django.contrib import admin

from .models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup


@admin.register(FlowLogEntry)
class FlowLogEntryAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "srcaddr",
        "srcport",
        "dstaddr",
        "dstport",
        "protocol",
        "action",
        "start_time",
        "end_time",
    )
    search_fields = ("srcaddr", "dstaddr", "interface_id", "account_id")
    list_filter = ("action", "protocol")


@admin.register(CorrelatedFlow)
class CorrelatedFlowAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "client_ip",
        "client_port",
        "server_ip",
        "server_port",
        "protocol",
        "flow_count",
        "last_seen",
    )
    search_fields = ("client_ip", "server_ip", "canonical_key")
    list_filter = ("protocol",)


@admin.register(IpMetadata)
class IpMetadataAdmin(admin.ModelAdmin):
    list_display = (
        "ip_address",
        "name",
        "asset_kind",
        "instance_id",
        "interface_id",
        "account_owner",
        "updated_at",
    )
    search_fields = (
        "ip_address",
        "name",
        "instance_id",
        "interface_id",
        "account_owner",
        "provider",
    )
    list_filter = ("asset_kind", "state", "region")


@admin.register(NetworkGroup)
class NetworkGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "cidr", "cidr_count", "kind", "updated_at")
    search_fields = ("name", "cidr")
    list_filter = ("kind",)

    @admin.display(description="CIDR count")
    def cidr_count(self, obj: NetworkGroup) -> int:
        return len(obj.cidr_values)
