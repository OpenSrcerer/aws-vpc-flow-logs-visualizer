from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable

from django.db.models import Q


class AdvancedFilterError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    pos: int


@dataclass(frozen=True)
class FieldRef:
    source: str
    name: str
    tag_key: str = ""


FIELD_ALIASES = {
    "addr.src": "srcaddr",
    "addr.dst": "dstaddr",
    "port.src": "srcport",
    "port.dst": "dstport",
    "proto": "protocol",
    "ip.src": "srcaddr",
    "ip.dst": "dstaddr",
}

SUPPORTED_FIELDS = {
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "action",
    "source",
    "interface_id",
    "log_status",
}

IP_FIELDS = {"srcaddr", "dstaddr"}
INT_FIELDS = {"srcport", "dstport", "protocol"}
STR_FIELDS = {"action", "source", "interface_id", "log_status"}
PROTOCOL_NAME_TO_NUMBER = {
    "icmp": 1,
    "ipip": 4,
    "ip-in-ip": 4,
    "ip_in_ip": 4,
    "ipinip": 4,
    "tcp": 6,
    "udp": 17,
}

INSTANCE_FIELD_ALIASES = {
    "instance.name": "name",
    "asset.name": "name",
    "instance.owner": "account_owner",
    "asset.owner": "account_owner",
    "instance.account_owner": "account_owner",
    "asset.account_owner": "account_owner",
    "instance.region": "region",
    "asset.region": "region",
    "instance.az": "availability_zone",
    "asset.az": "availability_zone",
    "instance.availability_zone": "availability_zone",
    "asset.availability_zone": "availability_zone",
    "instance.instance_id": "instance_id",
    "asset.instance_id": "instance_id",
    "instance.interface_id": "interface_id",
    "asset.interface_id": "interface_id",
    "instance.type": "instance_type",
    "asset.type": "instance_type",
    "instance.instance_type": "instance_type",
    "asset.instance_type": "instance_type",
    "instance.state": "state",
    "asset.state": "state",
    "instance.provider": "provider",
    "asset.provider": "provider",
    "instance.kind": "asset_kind",
    "asset.kind": "asset_kind",
    "instance.asset_kind": "asset_kind",
    "asset.asset_kind": "asset_kind",
}
INSTANCE_TAG_PREFIXES = ("instance.tags.", "asset.tags.")
INSTANCE_ATTRIBUTE_NAMES = {
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
}

INSTANCE_CONTEXT_ATTRIBUTES_KEY = "__instance_attributes"
INSTANCE_CONTEXT_TAGS_KEY = "__instance_tags"


def _tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(expression)

    while i < n:
        ch = expression[i]
        if ch.isspace():
            i += 1
            continue

        if ch == "(":
            tokens.append(Token("LPAREN", ch, i))
            i += 1
            continue

        if ch == ")":
            tokens.append(Token("RPAREN", ch, i))
            i += 1
            continue

        if expression.startswith("==", i) or expression.startswith("!=", i):
            tokens.append(Token("OP", expression[i : i + 2], i))
            i += 2
            continue
        if ch == "=":
            tokens.append(Token("OP", ch, i))
            i += 1
            continue

        if ch in {"'", '"'}:
            quote = ch
            start = i
            i += 1
            value_chars: list[str] = []
            while i < n:
                if expression[i] == "\\" and i + 1 < n:
                    value_chars.append(expression[i + 1])
                    i += 2
                    continue
                if expression[i] == quote:
                    i += 1
                    break
                value_chars.append(expression[i])
                i += 1
            else:
                raise AdvancedFilterError(f"Unterminated quoted string starting at position {start}.")
            tokens.append(Token("VALUE", "".join(value_chars), start))
            continue

        start = i
        while i < n and not expression[i].isspace() and expression[i] not in {"(", ")"}:
            if expression.startswith("==", i) or expression.startswith("!=", i) or expression[i] == "=":
                break
            i += 1

        word = expression[start:i]
        if not word:
            raise AdvancedFilterError(f"Unexpected token at position {start}.")

        lowered = word.lower()
        if lowered == "and":
            tokens.append(Token("AND", word, start))
        elif lowered == "or":
            tokens.append(Token("OR", word, start))
        else:
            tokens.append(Token("WORD", word, start))

    return tokens


class _Parser:
    def __init__(self, tokens: Iterable[Token]):
        self.tokens = list(tokens)
        self.idx = 0

    def parse(self) -> dict[str, Any]:
        if not self.tokens:
            raise AdvancedFilterError("Advanced filter is empty.")
        node = self._parse_or()
        if self._peek() is not None:
            token = self._peek()
            raise AdvancedFilterError(f"Unexpected token '{token.value}' at position {token.pos}.")
        return node

    def _peek(self) -> Token | None:
        if self.idx >= len(self.tokens):
            return None
        return self.tokens[self.idx]

    def _consume(self, expected_kind: str | None = None) -> Token:
        token = self._peek()
        if token is None:
            if expected_kind == "OP":
                raise AdvancedFilterError(
                    "Your filter looks incomplete after a field. Add `=`, `==`, or `!=` and a value."
                )
            if expected_kind == "RPAREN":
                raise AdvancedFilterError(
                    "Your filter is missing a closing `)`."
                )
            if expected_kind in {"WORD", "VALUE"}:
                raise AdvancedFilterError(
                    "Your filter looks incomplete after an operator. Add a value like `icmp`, `80`, or `10.0.0.0/16`."
                )
            raise AdvancedFilterError(
                "Your filter looks incomplete. Check for a missing value or closing `)`."
            )
        if expected_kind and token.kind != expected_kind:
            raise AdvancedFilterError(
                f"Expected {expected_kind} at position {token.pos}, got '{token.value}'."
            )
        self.idx += 1
        return token

    def _parse_or(self) -> dict[str, Any]:
        left = self._parse_and()
        while True:
            token = self._peek()
            if token is None or token.kind != "OR":
                break
            self._consume("OR")
            right = self._parse_and()
            left = {"type": "or", "left": left, "right": right}
        return left

    def _parse_and(self) -> dict[str, Any]:
        left = self._parse_primary()
        while True:
            token = self._peek()
            if token is None or token.kind != "AND":
                break
            self._consume("AND")
            right = self._parse_primary()
            left = {"type": "and", "left": left, "right": right}
        return left

    def _parse_primary(self) -> dict[str, Any]:
        token = self._peek()
        if token is None:
            raise AdvancedFilterError(
                "Your filter looks incomplete. Check for a missing value or closing `)`."
            )
        if token.kind == "LPAREN":
            self._consume("LPAREN")
            expr = self._parse_or()
            self._consume("RPAREN")
            return expr
        return self._parse_condition()

    def _parse_condition(self) -> dict[str, Any]:
        field_token = self._consume("WORD")
        op_token = self._consume("OP")
        if self._peek() is None:
            raise AdvancedFilterError(
                "Your filter looks incomplete after an operator. Add a value like `icmp`, `80`, or `10.0.0.0/16`."
            )
        value_token = self._consume()

        if value_token.kind not in {"WORD", "VALUE"}:
            raise AdvancedFilterError(
                f"Expected value at position {value_token.pos}, got '{value_token.value}'."
            )
        return {
            "type": "condition",
            "field": field_token.value,
            "op": op_token.value,
            "value": value_token.value,
        }


def parse_advanced_filter(expression: str) -> dict[str, Any]:
    parser = _Parser(_tokenize(expression))
    return parser.parse()


def _normalize_tag_map(value: Any) -> dict[str, str]:
    if value in (None, ""):
        return {}

    normalized: dict[str, str] = {}

    def add_tag(key: Any, tag_value: Any = "") -> None:
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

    text = str(value).strip()
    if not text:
        return {}
    if "=" in text:
        key, tag_value = text.split("=", 1)
        add_tag(key, tag_value)
    else:
        add_tag(text, "")
    return normalized


def inject_instance_context(
    row: dict[str, Any],
    *,
    src_meta: dict[str, Any] | None = None,
    dst_meta: dict[str, Any] | None = None,
) -> None:
    attributes: dict[str, list[Any]] = {}
    tags: dict[str, list[str]] = {}

    for meta in (src_meta, dst_meta):
        if not meta:
            continue

        for attr_name in INSTANCE_ATTRIBUTE_NAMES:
            raw_value = meta.get(attr_name)
            if raw_value in (None, ""):
                continue
            attributes.setdefault(attr_name, []).append(raw_value)

        for key, value in _normalize_tag_map(meta.get("tags")).items():
            key_text = str(key).strip().lower()
            if not key_text:
                continue
            tags.setdefault(key_text, []).append("" if value is None else str(value))

    row[INSTANCE_CONTEXT_ATTRIBUTES_KEY] = attributes
    row[INSTANCE_CONTEXT_TAGS_KEY] = tags


def _normalize_field(field_text: str) -> FieldRef:
    field_text = field_text.strip()
    field_key = field_text.lower()
    field_name = FIELD_ALIASES.get(field_key, field_key)
    if field_name not in SUPPORTED_FIELDS:
        instance_field = INSTANCE_FIELD_ALIASES.get(field_key)
        if instance_field:
            return FieldRef(source="instance_attr", name=instance_field)

        for prefix in INSTANCE_TAG_PREFIXES:
            if field_key.startswith(prefix):
                tag_key = field_text[len(prefix) :].strip().lower()
                if not tag_key:
                    raise AdvancedFilterError(
                        f"Missing tag key in '{field_text}'. Use `instance.tags.<KEY>`."
                    )
                return FieldRef(source="instance_tag", name="tags", tag_key=tag_key)

        supported_raw = ", ".join(sorted(SUPPORTED_FIELDS | set(FIELD_ALIASES.keys())))
        supported_instance = ", ".join(sorted(INSTANCE_FIELD_ALIASES.keys()))
        raise AdvancedFilterError(
            f"Unsupported field '{field_text}'. Supported raw fields: {supported_raw}. "
            f"Supported instance fields: {supported_instance}, instance.tags.<KEY>, asset.tags.<KEY>."
        )
    return FieldRef(source="raw", name=field_name)


def _parse_condition_value(field_ref: FieldRef, value_text: str) -> tuple[str, Any]:
    if field_ref.source == "raw" and field_ref.name in INT_FIELDS:
        if field_ref.name == "protocol":
            protocol_alias = PROTOCOL_NAME_TO_NUMBER.get(value_text.strip().lower())
            if protocol_alias is not None:
                return "int", protocol_alias
        try:
            return "int", int(value_text)
        except ValueError as exc:
            raise AdvancedFilterError(
                f"Expected integer value for '{field_ref.name}', got '{value_text}'."
            ) from exc

    if field_ref.source == "raw" and field_ref.name in IP_FIELDS:
        if "/" in value_text:
            try:
                return "cidr", ipaddress.ip_network(value_text, strict=False)
            except ValueError as exc:
                raise AdvancedFilterError(f"Invalid CIDR '{value_text}'.") from exc
        try:
            return "ip", str(ipaddress.ip_address(value_text))
        except ValueError as exc:
            raise AdvancedFilterError(f"Invalid IP address '{value_text}'.") from exc

    wildcard = "*" in value_text or "?" in value_text
    if wildcard:
        return "str_pattern", value_text.lower()
    return "str", value_text


def _get_field_values(row: dict[str, Any], field_ref: FieldRef) -> list[Any]:
    if field_ref.source == "raw":
        return [row.get(field_ref.name)]

    if field_ref.source == "instance_attr":
        values = row.get(INSTANCE_CONTEXT_ATTRIBUTES_KEY, {}).get(field_ref.name, [])
        if isinstance(values, list):
            return values
        return [values]

    if field_ref.source == "instance_tag":
        values = row.get(INSTANCE_CONTEXT_TAGS_KEY, {}).get(field_ref.tag_key, [])
        if isinstance(values, list):
            return values
        return [values]

    raise AdvancedFilterError(f"Unsupported field source '{field_ref.source}'.")


def _value_matches(value_kind: str, row_value: Any, value: Any) -> bool:
    if value_kind == "int":
        return row_value == value

    if value_kind == "ip":
        if not row_value:
            return False
        try:
            return str(ipaddress.ip_address(str(row_value))) == value
        except ValueError:
            return False

    if value_kind == "cidr":
        if not row_value:
            return False
        try:
            return ipaddress.ip_address(str(row_value)) in value
        except ValueError:
            return False

    if row_value is None:
        return False

    row_text = str(row_value)
    if value_kind == "str_pattern":
        return fnmatch.fnmatch(row_text.lower(), value)
    return row_text.lower() == str(value).lower()


def _evaluate_condition(row: dict[str, Any], field: str, op: str, value_text: str) -> bool:
    op = "==" if op == "=" else op
    if op not in {"==", "!="}:
        raise AdvancedFilterError(f"Unsupported operator '{op}'. Only =, ==, and != are supported.")

    field_ref = _normalize_field(field)
    value_kind, value = _parse_condition_value(field_ref, value_text)
    row_values = _get_field_values(row, field_ref)
    matched = any(_value_matches(value_kind, row_value, value) for row_value in row_values)

    return matched if op == "==" else not matched


def validate_advanced_filter_ast(ast: dict[str, Any]) -> None:
    node_type = ast.get("type")
    if node_type == "condition":
        op = ast.get("op")
        if op not in {"=", "==", "!="}:
            raise AdvancedFilterError(f"Unsupported operator '{op}'. Only =, ==, and != are supported.")
        field_ref = _normalize_field(str(ast.get("field", "")))
        _parse_condition_value(field_ref, str(ast.get("value", "")))
        return

    if node_type in {"and", "or"}:
        left = ast.get("left")
        right = ast.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise AdvancedFilterError("Malformed boolean expression.")
        validate_advanced_filter_ast(left)
        validate_advanced_filter_ast(right)
        return

    raise AdvancedFilterError(f"Unsupported AST node type '{node_type}'.")


def evaluate_advanced_filter(ast: dict[str, Any], row: dict[str, Any]) -> bool:
    node_type = ast.get("type")
    if node_type == "condition":
        return _evaluate_condition(row, ast["field"], ast["op"], ast["value"])
    if node_type == "and":
        return evaluate_advanced_filter(ast["left"], row) and evaluate_advanced_filter(ast["right"], row)
    if node_type == "or":
        return evaluate_advanced_filter(ast["left"], row) or evaluate_advanced_filter(ast["right"], row)
    raise AdvancedFilterError(f"Unsupported AST node type '{node_type}'.")


def _compile_condition_to_q(condition: dict[str, Any]) -> Q | None:
    op = "==" if condition["op"] == "=" else condition["op"]
    if op not in {"==", "!="}:
        raise AdvancedFilterError(f"Unsupported operator '{condition['op']}'. Only =, ==, and != are supported.")

    field_ref = _normalize_field(str(condition["field"]))
    if field_ref.source != "raw":
        return None

    value_kind, value = _parse_condition_value(field_ref, str(condition["value"]))
    field_name = field_ref.name

    if value_kind in {"int", "ip"}:
        compiled_match = Q(**{field_name: value})
    elif value_kind == "str":
        compiled_match = Q(**{f"{field_name}__iexact": str(value)})
    else:
        # CIDR and wildcard filters are evaluated in Python for compatibility
        # across SQLite/PostgreSQL deployments.
        return None

    if op == "==":
        return compiled_match

    # Python evaluator treats NULL row values as "not equal"; preserve that
    # behavior in SQL by explicitly including NULLs.
    return Q(**{f"{field_name}__isnull": True}) | ~compiled_match


def build_prefilter_q_from_advanced_filter_ast(ast: dict[str, Any]) -> Q | None:
    """
    Best-effort compiler from advanced-filter AST to Django Q objects.

    Returns a safe prefilter Q expression when possible:
    - fully compilable expressions return exact semantics
    - partially compilable `AND` expressions return a narrowing prefilter
    - expressions that cannot be compiled safely return None
    """
    node_type = ast.get("type")
    if node_type == "condition":
        return _compile_condition_to_q(ast)

    if node_type == "and":
        left = build_prefilter_q_from_advanced_filter_ast(ast["left"])
        right = build_prefilter_q_from_advanced_filter_ast(ast["right"])
        if left is None:
            return right
        if right is None:
            return left
        return left & right

    if node_type == "or":
        left = build_prefilter_q_from_advanced_filter_ast(ast["left"])
        right = build_prefilter_q_from_advanced_filter_ast(ast["right"])
        if left is None or right is None:
            return None
        return left | right

    raise AdvancedFilterError(f"Unsupported AST node type '{node_type}'.")


def advanced_filter_can_run_in_db(ast: dict[str, Any]) -> bool:
    node_type = ast.get("type")
    if node_type == "condition":
        return _compile_condition_to_q(ast) is not None
    if node_type in {"and", "or"}:
        return advanced_filter_can_run_in_db(ast["left"]) and advanced_filter_can_run_in_db(ast["right"])
    raise AdvancedFilterError(f"Unsupported AST node type '{node_type}'.")
