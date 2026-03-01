import base64
import os
from dataclasses import dataclass

from rest_framework import permissions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed


def _parse_account(value: str | None) -> tuple[str, str] | None:
    text = str(value or "").strip()
    if not text or ":" not in text:
        return None

    username, password = text.split(":", 1)
    username = username.strip()
    if not username:
        return None

    return username, password


def get_env_account_config() -> dict:
    write_account = _parse_account(os.getenv("WRITE_ACCOUNT"))
    read_account = _parse_account(os.getenv("READ_ACCOUNT"))
    return {
        "enabled": bool(write_account or read_account),
        "write": write_account,
        "read": read_account,
    }


@dataclass
class EnvAccountUser:
    username: str
    role: str

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @property
    def is_staff(self) -> bool:
        return self.role == "write"

    @property
    def is_superuser(self) -> bool:
        return False


class EnvAccountAuthentication(BaseAuthentication):
    def authenticate(self, request):
        config = get_env_account_config()
        if not config["enabled"]:
            return None

        auth_header = get_authorization_header(request).split()
        if not auth_header:
            raise AuthenticationFailed("Authentication credentials were not provided.")

        if len(auth_header) != 2 or auth_header[0].lower() != b"basic":
            raise AuthenticationFailed("Invalid authorization header.")

        try:
            decoded = base64.b64decode(auth_header[1]).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuthenticationFailed("Invalid basic auth credentials.") from exc

        if ":" not in decoded:
            raise AuthenticationFailed("Invalid basic auth credentials.")

        username, password = decoded.split(":", 1)

        write_account = config["write"]
        if write_account and username == write_account[0] and password == write_account[1]:
            return EnvAccountUser(username=username, role="write"), None

        read_account = config["read"]
        if read_account and username == read_account[0] and password == read_account[1]:
            return EnvAccountUser(username=username, role="read"), None

        raise AuthenticationFailed("Invalid username or password.")

    def authenticate_header(self, request):
        return 'Basic realm="AWS VPC Flow Logs Visualizer API"'


class EnvAccountPermission(permissions.BasePermission):
    message = "Write account credentials are required for this operation."

    def has_permission(self, request, view):
        config = get_env_account_config()
        if not config["enabled"]:
            return True

        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False

        role = getattr(user, "role", "")
        if role == "write":
            return True

        return request.method in permissions.SAFE_METHODS and role == "read"
