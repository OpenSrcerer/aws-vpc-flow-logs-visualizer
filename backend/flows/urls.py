from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AdvancedFlowFilterValidateView,
    CorrelatedFlowViewSet,
    CorrelationRebuildView,
    FirewallRecommendationView,
    FlowLogEntryViewSet,
    FlowLogImportListView,
    FlowLogPurgeView,
    FlowLogUploadView,
    GlobalSearchView,
    HealthView,
    IpMetadataImportView,
    IpMetadataViewSet,
    MeshGraphView,
    NetworkGroupImportView,
    NetworkGroupPurgeView,
    NetworkGroupViewSet,
)

router = DefaultRouter()
router.register("flow-logs", FlowLogEntryViewSet, basename="flow-logs")
router.register("correlated-flows", CorrelatedFlowViewSet, basename="correlated-flows")
router.register("ip-metadata", IpMetadataViewSet, basename="ip-metadata")
router.register("network-groups", NetworkGroupViewSet, basename="network-groups")

urlpatterns = [
    path("", include(router.urls)),
    path("health/", HealthView.as_view(), name="health"),
    path("search/", GlobalSearchView.as_view(), name="global-search"),
    path("uploads/flow-logs/", FlowLogUploadView.as_view(), name="upload-flow-logs"),
    path("metadata/import/", IpMetadataImportView.as_view(), name="import-ip-metadata"),
    path(
        "maintenance/network-groups/import/",
        NetworkGroupImportView.as_view(),
        name="import-network-groups",
    ),
    path("correlation/rebuild/", CorrelationRebuildView.as_view(), name="correlation-rebuild"),
    path(
        "maintenance/flow-logs/validate-filter/",
        AdvancedFlowFilterValidateView.as_view(),
        name="flow-log-validate-filter",
    ),
    path("maintenance/flow-logs/imports/", FlowLogImportListView.as_view(), name="flow-log-imports"),
    path("maintenance/flow-logs/purge/", FlowLogPurgeView.as_view(), name="flow-log-purge"),
    path("maintenance/network-groups/purge/", NetworkGroupPurgeView.as_view(), name="network-group-purge"),
    path("mesh/", MeshGraphView.as_view(), name="mesh"),
    path("firewall/recommendations/", FirewallRecommendationView.as_view(), name="firewall-recommendations"),
]
