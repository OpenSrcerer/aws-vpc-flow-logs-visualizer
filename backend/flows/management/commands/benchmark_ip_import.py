import time
from django.core.management.base import BaseCommand
from django.test import RequestFactory
from flows.views import IpMetadataImportView
from flows.models import IpMetadata

class Command(BaseCommand):
    help = "Benchmark IpMetadataImportView"

    def handle(self, *args, **options):
        # Setup
        IpMetadata.objects.all().delete()
        factory = RequestFactory()
        view = IpMetadataImportView.as_view()

        # Generate test data
        items = []
        for i in range(2000):
            items.append({
                "ip_address": f"10.0.{i // 256}.{i % 256}",
                "name": f"Test IP {i}",
                "provider": "Test Provider",
                "tags": ["test", "benchmark"],
                "attributes": {"attr": i}
            })

        request = factory.post(
            "/api/ip-metadata/import/",
            {"items": items},
            content_type="application/json"
        )

        print("Running benchmark with 2000 items (insert)...")
        start_time = time.time()
        response = view(request)
        insert_time = time.time() - start_time
        print(f"Insert Time: {insert_time:.4f} seconds")
        print(f"Response: {response.data}")

        # Now do it again to benchmark update
        for i in range(2000):
            items[i]["name"] = f"Test IP Updated {i}"

        request_update = factory.post(
            "/api/ip-metadata/import/",
            {"items": items},
            content_type="application/json"
        )

        print("Running benchmark with 2000 items (update)...")
        start_time = time.time()
        response_update = view(request_update)
        update_time = time.time() - start_time
        print(f"Update Time: {update_time:.4f} seconds")
        print(f"Response: {response_update.data}")

        # Cleanup
        IpMetadata.objects.all().delete()
