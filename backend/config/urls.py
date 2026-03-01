from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView
from django.views.static import serve as static_serve
from rest_framework.permissions import AllowAny
from rest_framework.renderers import JSONOpenAPIRenderer
from rest_framework.schemas import get_schema_view

schema_view = get_schema_view(
    title="AWS VPC Flow Logs Visualizer API",
    description="OpenAPI schema for the backend APIs.",
    version="1.0.0",
    public=True,
    permission_classes=[AllowAny],
    renderer_classes=[JSONOpenAPIRenderer],
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/schema/", schema_view, name="openapi-schema"),
    path(
        "api/docs/",
        TemplateView.as_view(
            template_name="docs/swagger-ui.html",
            extra_context={"schema_url_name": "openapi-schema"},
        ),
        name="swagger-ui",
    ),
    path(
        "api/redoc/",
        TemplateView.as_view(
            template_name="docs/redoc.html",
            extra_context={"schema_url_name": "openapi-schema"},
        ),
        name="redoc",
    ),
    path("api/", include("flows.urls")),
]

if settings.FRONTEND_DIST_DIR.exists():
    frontend_index_view = TemplateView.as_view(template_name="index.html")
    urlpatterns += [
        re_path(
            r"^assets/(?P<path>.*)$",
            static_serve,
            {"document_root": settings.FRONTEND_ASSETS_DIR},
        ),
        re_path(
            r"^(?P<path>(?:favicon\.ico|robots\.txt|manifest\.webmanifest))$",
            static_serve,
            {"document_root": settings.FRONTEND_DIST_DIR},
        ),
        path("", frontend_index_view, name="frontend-index"),
        re_path(r"^(?!api/|admin/|assets/).*$", frontend_index_view, name="frontend-spa"),
    ]
