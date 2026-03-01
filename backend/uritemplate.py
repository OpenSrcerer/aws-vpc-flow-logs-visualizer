"""
Minimal URI template helpers required by DRF OpenAPI generation.

Only ``variables`` is required for this project.
"""

import re

VARIABLE_PATTERN = re.compile(r"\{([^}]+)\}")


def variables(template: str) -> list[str]:
    if not template:
        return []
    return [match.strip() for match in VARIABLE_PATTERN.findall(str(template)) if match.strip()]
