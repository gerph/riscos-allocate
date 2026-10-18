#!/usr/bin/env python3
"""
Display the contents of Allocate request files.
"""

from __future__ import annotations

import argparse
import base64
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


MAGIC = b"ALLOCATE"
HEADER_STRUCT = struct.Struct("<8sii")
OBJECT_HEADER_STRUCT = struct.Struct("<ii")
TOP_LEVEL_KEYS = {"SchemaVersion", "FormatVersion", "Developer", "Registrations"}
DEVELOPER_FIELDS = [
    ("Name", "name", 40),
    ("Company", "company", 50),
    ("DeveloperNumber", "developer_number", 12),
    ("Address1", "address1", 50),
    ("Address2", "address2", 50),
    ("Address3", "address3", 50),
    ("Address4", "address4", 50),
    ("Phone", "phone", 50),
    ("Fax", "fax", 50),
    ("Email", "email", 50),
]

OBJECT_NAME_TO_ID = {
    "SWIChunk": 0,
    "MessageBlock": 1,
    "Reservation": 2,
    "Filetype": 3,
    "ErrorBlock": 4,
    "Podule": 5,
    "DrawTagBlock": 6,
    "DrawObjectBlock": 7,
    "FilingSystem": 8,
    "ServiceBlock": 9,
    "Device": 10,
}

OBJECT_ALIASES = {
    "SWI chunk": "SWIChunk",
    "SWIChunk": "SWIChunk",
    "SWIchunk": "SWIChunk",
    "Message block": "MessageBlock",
    "MessageBlock": "MessageBlock",
    "Messageblock": "MessageBlock",
    "Reservation": "Reservation",
    "Filetype": "Filetype",
    "Error block": "ErrorBlock",
    "ErrorBlock": "ErrorBlock",
    "Errorblock": "ErrorBlock",
    "Podule": "Podule",
    "Draw tag block": "DrawTagBlock",
    "DrawTagBlock": "DrawTagBlock",
    "Drawtagblock": "DrawTagBlock",
    "Draw object block": "DrawObjectBlock",
    "DrawObjectBlock": "DrawObjectBlock",
    "Drawobjectblock": "DrawObjectBlock",
    "Filing system": "FilingSystem",
    "FilingSystem": "FilingSystem",
    "Filingsystem": "FilingSystem",
    "Service block": "ServiceBlock",
    "ServiceBlock": "ServiceBlock",
    "Serviceblock": "ServiceBlock",
    "Device": "Device",
}


class ParseError(Exception):
    """
    Raised when an Allocate file cannot be parsed.
    """


@dataclass
class AttachmentInfo:
    """
    Information about an embedded binary attachment.
    """

    kind: str
    size: int
    data: bytes


def decode_text(data: bytes) -> str:
    """
    Decode a fixed-length Allocate text field.
    """

    return data.split(b"\0", 1)[0].decode("latin-1", errors="replace").strip()


def read_exact(stream: BinaryIO, size: int, context: str) -> bytes:
    """
    Read exactly size bytes or raise a parse error.
    """

    data = stream.read(size)
    if len(data) != size:
        raise ParseError("Unexpected end of file while reading {}".format(context))
    return data


def read_i32(buffer: bytes, offset: int, context: str) -> tuple[int, int]:
    """
    Read a little-endian 32-bit integer from a buffer.
    """

    end = offset + 4
    if end > len(buffer):
        raise ParseError("Object payload too short while reading {}".format(context))
    return struct.unpack_from("<i", buffer, offset)[0], end


def format_version(version: int) -> str:
    """
    Format an integer version field as decimal.major.
    """

    return "{}.{:02d}".format(version // 100, version % 100)


def parse_details_block(data: bytes) -> dict[str, str]:
    """
    Parse the 452-byte developer details block.
    """

    if len(data) != 452:
        raise ParseError("Developer details block has unexpected size {}".format(len(data)))

    layout = [
        ("name", 40),
        ("company", 50),
        ("developer_number", 12),
        ("address1", 50),
        ("address2", 50),
        ("address3", 50),
        ("address4", 50),
        ("phone", 50),
        ("fax", 50),
        ("email", 50),
    ]

    details: dict[str, str] = {}
    offset = 0
    for name, size in layout:
        details[name] = decode_text(data[offset : offset + size])
        offset += size
    return details


def parse_filetype_payload(payload: bytes) -> dict[str, object]:
    """
    Parse the variable-length filetype object payload.
    """

    minimum = 12 + 9 + 4
    if len(payload) < minimum:
        raise ParseError("Filetype object payload is too short")

    appname = decode_text(payload[0:12])
    fname = decode_text(payload[12:21])
    parse_errors: list[str] = []

    # Historical files were written from a 32-bit C structure, which places
    # 3 bytes of padding between the 9-byte fname field and the BOOL.
    for flag_offset, size_offset in ((24, 28), (21, 25)):
        try:
            double_clicking, _ = read_i32(
                payload, flag_offset, "filetype double-click flag"
            )
            offset = size_offset
            attachments: list[AttachmentInfo] = []
            for label in ("sprite", "product description", "format description"):
                size, offset = read_i32(payload, offset, "{} size".format(label))
                if size < 0:
                    raise ParseError("{} attachment has negative size {}".format(label, size))
                end = offset + size
                if end > len(payload):
                    raise ParseError("{} attachment overruns the object payload".format(label))
                attachments.append(AttachmentInfo(label, size, payload[offset:end]))
                offset = end

            if offset != len(payload):
                raise ParseError(
                    "Filetype object has {} trailing byte(s)".format(len(payload) - offset)
                )

            return {
                "application_name": appname,
                "filetype_name": fname,
                "double_clicking": bool(double_clicking),
                "attachments": attachments,
            }
        except ParseError as exc:
            parse_errors.append(str(exc))

    raise ParseError("; ".join(parse_errors))


def parse_object_payload(object_id: int, payload: bytes) -> tuple[str, dict[str, object]]:
    """
    Parse an object payload based on its object identifier.
    """

    if object_id == 0:
        return "SWI chunk", {
            "prefix": decode_text(payload[:20]),
            "description": decode_text(payload[20:120]),
        }
    if object_id == 1:
        return "Message block", {"description": decode_text(payload[:100])}
    if object_id == 2:
        return "Reservation", {
            "text": decode_text(payload[:40]),
            "type": decode_text(payload[40:60]),
        }
    if object_id == 3:
        return "Filetype", parse_filetype_payload(payload)
    if object_id == 4:
        return "Error block", {"description": decode_text(payload[:100])}
    if object_id == 5:
        if len(payload) < 128:
            raise ParseError("Podule object payload is too short")
        allocate_manf = struct.unpack_from("<i", payload, 0)[0]
        manf = struct.unpack_from("<i", payload, 4)[0]
        return "Podule", {
            "allocate_manufacturer": bool(allocate_manf),
            "manufacturer_id": manf,
            "podule_name": decode_text(payload[8:28]),
            "description": decode_text(payload[28:128]),
        }
    if object_id == 6:
        return "Draw tag block", {"description": decode_text(payload[:100])}
    if object_id == 7:
        return "Draw object block", {"description": decode_text(payload[:100])}
    if object_id == 8:
        return "Filing system", {
            "name": decode_text(payload[:20]),
            "selector": decode_text(payload[20:40]),
        }
    if object_id == 9:
        return "Service block", {"description": decode_text(payload[:100])}
    if object_id == 10:
        return "Device", {
            "name": decode_text(payload[:20]),
            "description": decode_text(payload[20:120]),
        }

    return "Unknown object ({})".format(object_id), {"raw_payload_size": len(payload)}


def require_size(payload: bytes, size: int, name: str) -> None:
    """
    Validate that a fixed-size payload is large enough.
    """

    if len(payload) < size:
        raise ParseError("{} payload is too short: expected {}, got {}".format(name, size, len(payload)))


def parse_object(index: int, stream: BinaryIO) -> dict[str, object]:
    """
    Parse a single object record.
    """

    header = read_exact(stream, OBJECT_HEADER_STRUCT.size, "object {} header".format(index))
    object_id, size = OBJECT_HEADER_STRUCT.unpack(header)
    if size < 0:
        raise ParseError("Object {} has negative size {}".format(index, size))

    payload = read_exact(stream, size, "object {} payload".format(index))

    fixed_sizes = {
        0: 120,
        1: 100,
        2: 60,
        4: 100,
        5: 128,
        6: 100,
        7: 100,
        8: 40,
        9: 100,
        10: 120,
    }
    if object_id in fixed_sizes:
        require_size(payload, fixed_sizes[object_id], "object {}".format(index))

    name, values = parse_object_payload(object_id, payload)
    return {
        "index": index,
        "id": object_id,
        "name": name,
        "size": size,
        "values": values,
    }


def parse_allocate_file(path: Path) -> dict[str, object]:
    """
    Parse an Allocate request file.
    """

    with path.open("rb") as stream:
        header = read_exact(stream, HEADER_STRUCT.size, "file header")
        magic, version, object_count = HEADER_STRUCT.unpack(header)

        if magic != MAGIC:
            raise ParseError(
                "Bad file header: expected {!r}, found {!r}".format(MAGIC, magic)
            )
        if object_count < 0:
            raise ParseError("Negative object count {}".format(object_count))

        details = parse_details_block(read_exact(stream, 452, "developer details"))
        objects = [
            parse_object(index + 1, stream) for index in range(object_count)
        ]
        trailing = stream.read()

    return {
        "path": path,
        "version": version,
        "object_count": object_count,
        "details": details,
        "objects": objects,
        "trailing_bytes": len(trailing),
    }


def print_key_value(label: str, value: object, indent: str = "") -> None:
    """
    Print a formatted key/value pair.
    """

    print("{}{}: {}".format(indent, label, value))


def decode_latin1_text(data: bytes) -> str:
    """
    Decode attachment text fields as Latin-1.
    """

    return data.decode("latin-1", errors="replace")


def yaml_quote(value: str) -> str:
    """
    Quote a scalar for YAML output.
    """

    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return '"{}"'.format(escaped)


def yaml_safe_key(name: str) -> str:
    """
    Return a YAML-safe key token.
    """

    if all(ch.isalnum() or ch in "_-" for ch in name):
        return name
    return yaml_quote(name)


def yaml_scalar(value: object) -> str:
    """
    Format a simple scalar value for YAML output.
    """

    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if text == "":
        return '""'
    lower = text.lower()
    if lower in ("null", "true", "false", "~"):
        return yaml_quote(text)
    if text[0].isspace() or text[-1].isspace():
        return yaml_quote(text)
    special = ":#{}[]&*!|>'\"%@`"
    if any(ch in text for ch in "\n\r") or any(ch in special for ch in text):
        return yaml_quote(text)
    return text


def emit_yaml_block(lines: list[str], key: str, value: str, indent: int) -> None:
    """
    Emit a literal block scalar.
    """

    prefix = " " * indent
    lines.append("{}{}: |".format(prefix, key))
    for line in value.splitlines():
        lines.append("{}  {}".format(prefix, line))
    if value.endswith("\n"):
        lines.append("{}  ".format(prefix))


def attachment_filename(index: int, object_name: str, field_name: str, suffix: str) -> str:
    """
    Generate a deterministic detached filename for an attachment.
    """

    safe_object = object_name.replace(" ", "")
    return "{}-{}-{}{}".format(index, safe_object, field_name, suffix)


def registration_yaml_name(object_name: str) -> str:
    """
    Return the exported YAML object type name.
    """

    return object_name.replace(" ", "")


def developer_to_yaml(details: dict[str, str], version: int) -> list[str]:
    """
    Convert the developer details block to YAML lines.
    """

    lines = ["SchemaVersion: 1", "FormatVersion: {}".format(yaml_scalar(format_version(version))), "Developer:"]
    labels = [
        ("Name", "name"),
        ("Company", "company"),
        ("DeveloperNumber", "developer_number"),
        ("Address1", "address1"),
        ("Address2", "address2"),
        ("Address3", "address3"),
        ("Address4", "address4"),
        ("Phone", "phone"),
        ("Fax", "fax"),
        ("Email", "email"),
    ]
    for label, key in labels:
        value = details[key] or None
        lines.append("  {}: {}".format(label, yaml_scalar(value)))
    return lines


def filetype_yaml_fields(
    obj: dict[str, object],
    values: dict[str, object],
    extract_dir: Path | None,
) -> tuple[list[tuple[str, object, bool]], list[tuple[str, bytes]]]:
    """
    Build YAML fields and detached files for a filetype object.
    """

    fields: list[tuple[str, object, bool]] = [
        ("ApplicationName", values["application_name"] or None, False),
        ("Name", values["filetype_name"] or None, False),
        ("DoubleClicking", values["double_clicking"], False),
    ]
    files_to_write: list[tuple[str, bytes]] = []

    attachment_map = {
        "sprite": ("Sprite", "SpriteFile", ",ff9"),
        "product description": ("ProductDescription", "ProductDescriptionFile", ".txt"),
        "format description": ("FormatDescription", "FormatDescriptionFile", ".txt"),
    }

    for attachment in values["attachments"]:
        inline_key, file_key, suffix = attachment_map[attachment.kind]
        if extract_dir is None:
            if attachment.kind == "sprite":
                fields.append((inline_key, base64.b64encode(attachment.data).decode("ascii"), True))
            else:
                fields.append((inline_key, decode_latin1_text(attachment.data), True))
            continue

        filename = attachment_filename(obj["index"], obj["name"], inline_key, suffix)
        fields.append((file_key, filename, False))
        files_to_write.append((filename, attachment.data))

    return fields, files_to_write


def object_to_yaml(
    obj: dict[str, object],
    extract_dir: Path | None,
) -> tuple[list[str], list[tuple[str, bytes]]]:
    """
    Convert one object to YAML lines and detached files.
    """

    fields: list[tuple[str, object, bool]]
    files_to_write: list[tuple[str, bytes]] = []
    values = obj["values"]

    if obj["id"] == 3:
        fields, files_to_write = filetype_yaml_fields(obj, values, extract_dir)
    elif obj["id"] == 0:
        fields = [("Prefix", values["prefix"] or None, False), ("Description", values["description"] or None, False)]
    elif obj["id"] == 1:
        fields = [("Description", values["description"] or None, False)]
    elif obj["id"] == 2:
        fields = [("Type", values["type"] or None, False), ("Text", values["text"] or None, False)]
    elif obj["id"] == 4:
        fields = [("Description", values["description"] or None, False)]
    elif obj["id"] == 5:
        fields = [
            ("AllocateManufacturer", values["allocate_manufacturer"], False),
            ("ManufacturerId", values["manufacturer_id"], False),
            ("PoduleName", values["podule_name"] or None, False),
            ("Description", values["description"] or None, False),
        ]
    elif obj["id"] == 6:
        fields = [("Description", values["description"] or None, False)]
    elif obj["id"] == 7:
        fields = [("Description", values["description"] or None, False)]
    elif obj["id"] == 8:
        fields = [("Name", values["name"] or None, False), ("Selector", values["selector"] or None, False)]
    elif obj["id"] == 9:
        fields = [("Description", values["description"] or None, False)]
    elif obj["id"] == 10:
        fields = [("Name", values["name"] or None, False), ("Description", values["description"] or None, False)]
    else:
        fields = [("RawPayloadSize", values["raw_payload_size"], False)]

    lines = ["  - {}:".format(registration_yaml_name(obj['name']))]
    for key, value, literal in fields:
        if literal and isinstance(value, str):
            emit_yaml_block(lines, key, value, 6)
        else:
            lines.append("      {}: {}".format(yaml_safe_key(key), yaml_scalar(value)))
    return lines, files_to_write


def build_yaml(parsed: dict[str, object], extract_dir: Path | None = None) -> tuple[str, list[tuple[str, bytes]]]:
    """
    Build the extracted YAML description and detached file list.
    """

    lines = developer_to_yaml(parsed["details"], parsed["version"])
    lines.append("Registrations:")

    files_to_write: list[tuple[str, bytes]] = []
    for obj in parsed["objects"]:
        obj_lines, obj_files = object_to_yaml(obj, extract_dir)
        lines.extend(obj_lines)
        files_to_write.extend(obj_files)

    lines.append("")
    return "\n".join(lines), files_to_write


def write_extract_files(parsed: dict[str, object], output_dir: Path) -> None:
    """
    Write the YAML export and detached files to a directory.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    yaml_text, files_to_write = build_yaml(parsed, extract_dir=output_dir)
    output_dir.joinpath("Allocation.yaml").write_text(yaml_text, encoding="utf-8")
    for filename, data in files_to_write:
        output_dir.joinpath(filename).write_bytes(data)


def warn(warnings: list[str], message: str) -> None:
    """
    Record a warning.
    """

    warnings.append(message)


def count_indent(line: str) -> int:
    """
    Count leading spaces in a YAML line.
    """

    return len(line) - len(line.lstrip(" "))


def decode_yaml_double_quoted(value: str) -> str:
    """
    Decode a limited YAML double-quoted scalar.
    """

    chars: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != "\\":
            chars.append(ch)
            i += 1
            continue

        i += 1
        if i >= len(value):
            chars.append("\\")
            break

        esc = value[i]
        chars.append(
            {
                "n": "\n",
                "r": "\r",
                "t": "\t",
                '"': '"',
                "\\": "\\",
            }.get(esc, esc)
        )
        i += 1

    return "".join(chars)


def parse_yaml_scalar_text(value: str) -> object:
    """
    Parse the subset of YAML scalars emitted by this tool.
    """

    value = value.strip()
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return decode_yaml_double_quoted(value[1:-1])
    return value


class SimpleYamlParser:
    """
    Parse the limited YAML subset used by allocate_dump.
    """

    def __init__(self, text: str):
        self.lines = text.splitlines()
        self.line_count = len(self.lines)

    def is_blank(self, index: int) -> bool:
        """
        Return whether the line is empty or a comment.
        """

        stripped = self.lines[index].strip()
        return stripped == "" or stripped.startswith("#")

    def next_significant(self, index: int) -> int:
        """
        Skip blank lines and comments.
        """

        while index < self.line_count and self.is_blank(index):
            index += 1
        return index

    def parse(self) -> tuple[dict[str, object], list[str]]:
        """
        Parse a full document.
        """

        warnings: list[str] = []
        mapping, index = self.parse_mapping(0, 0, warnings)
        index = self.next_significant(index)
        if index < self.line_count:
            warn(warnings, "Unexpected trailing content at line {}".format(index + 1))
        return mapping, warnings

    def parse_mapping(
        self, index: int, indent: int, warnings: list[str]
    ) -> tuple[dict[str, object], int]:
        """
        Parse a mapping block.
        """

        result: dict[str, object] = {}
        while True:
            index = self.next_significant(index)
            if index >= self.line_count:
                return result, index

            line = self.lines[index]
            current_indent = count_indent(line)
            if current_indent < indent:
                return result, index
            if current_indent > indent:
                warn(
                    warnings,
                    "Unexpected indentation at line {}; treating as nested content".format(index + 1),
                )
                return result, index

            stripped = line[current_indent:]
            if stripped.startswith("- "):
                return result, index

            match = re.match(r"([^:]+):(.*)$", stripped)
            if not match:
                warn(warnings, "Malformed mapping entry at line {}".format(index + 1))
                index += 1
                continue

            key = match.group(1).strip()
            remainder = match.group(2).lstrip()
            if key in result:
                warn(warnings, "Duplicate key {!r} at line {}; overwriting".format(key, index + 1))

            if remainder == "|":
                value, index = self.parse_block_scalar(index + 1, indent, warnings)
            elif remainder == "":
                value, index = self.parse_nested_value(index + 1, indent, warnings)
            else:
                value = parse_yaml_scalar_text(remainder)
                index += 1

            result[key] = value

    def parse_sequence(
        self, index: int, indent: int, warnings: list[str]
    ) -> tuple[list[object], int]:
        """
        Parse a sequence block.
        """

        result: list[object] = []
        while True:
            index = self.next_significant(index)
            if index >= self.line_count:
                return result, index

            line = self.lines[index]
            current_indent = count_indent(line)
            if current_indent < indent:
                return result, index
            if current_indent != indent:
                warn(warnings, "Unexpected sequence indentation at line {}".format(index + 1))
                return result, index

            stripped = line[current_indent:]
            if not stripped.startswith("- "):
                return result, index

            remainder = stripped[2:]
            if remainder == "":
                value, index = self.parse_nested_value(index + 1, indent + 2, warnings)
                result.append(value)
                continue

            match = re.match(r"([^:]+):(.*)$", remainder)
            if match:
                key = match.group(1).strip()
                tail = match.group(2).lstrip()
                if tail == "|":
                    scalar, index = self.parse_block_scalar(index + 1, indent + 2, warnings)
                    result.append({key: scalar})
                    continue
                if tail == "":
                    value, index = self.parse_nested_value(index + 1, indent + 2, warnings)
                    result.append({key: value})
                    continue
                result.append({key: parse_yaml_scalar_text(tail)})
                index += 1
                continue

            result.append(parse_yaml_scalar_text(remainder))
            index += 1

    def parse_nested_value(
        self, index: int, parent_indent: int, warnings: list[str]
    ) -> tuple[object, int]:
        """
        Parse the value nested under a mapping key or sequence item.
        """

        index = self.next_significant(index)
        if index >= self.line_count:
            warn(warnings, "Expected nested content at end of file")
            return {}, index

        line = self.lines[index]
        indent = count_indent(line)
        if indent <= parent_indent:
            warn(warnings, "Expected nested content at line {}".format(index + 1))
            return {}, index

        if line[indent:].startswith("- "):
            return self.parse_sequence(index, indent, warnings)
        return self.parse_mapping(index, indent, warnings)

    def parse_block_scalar(
        self, index: int, parent_indent: int, warnings: list[str]
    ) -> tuple[str, int]:
        """
        Parse a literal block scalar.
        """

        index = self.next_significant(index)
        if index >= self.line_count:
            warn(warnings, "Expected block scalar content at end of file")
            return "", index

        required_indent = parent_indent + 2
        first_indent = count_indent(self.lines[index])
        if first_indent < required_indent:
            warn(warnings, "Expected block scalar content at line {}".format(index + 1))
            return "", index

        lines: list[str] = []
        while index < self.line_count:
            raw = self.lines[index]
            if raw.strip() == "":
                if count_indent(raw) >= required_indent:
                    lines.append("")
                    index += 1
                    continue
                break

            indent = count_indent(raw)
            if indent < required_indent:
                break

            lines.append(raw[required_indent:])
            index += 1

        return "\n".join(lines), index


def encode_text_field(
    value: object, size: int, context: str, warnings: list[str]
) -> bytes:
    """
    Encode a fixed-width Latin-1 text field.
    """

    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    else:
        warn(warnings, "{} should be text; converting from {}".format(context, type(value).__name__))
        text = str(value)

    encoded = text.encode("latin-1", errors="replace")
    if encoded.decode("latin-1") != text:
        warn(warnings, "{} contains characters outside Latin-1; replaced with '?'".format(context))
    if len(encoded) > size:
        warn(warnings, "{} exceeds {} bytes; truncating".format(context, size))
    return encoded[:size].ljust(size, b"\0")


def encode_attachment_text(value: object, context: str, warnings: list[str]) -> bytes:
    """
    Encode a Latin-1 attachment.
    """

    if value is None:
        warn(warnings, "{} missing; using empty content".format(context))
        text = ""
    elif isinstance(value, str):
        text = value
    else:
        warn(warnings, "{} should be text; converting from {}".format(context, type(value).__name__))
        text = str(value)

    encoded = text.encode("latin-1", errors="replace")
    if encoded.decode("latin-1") != text:
        warn(warnings, "{} contains characters outside Latin-1; replaced with '?'".format(context))
    return encoded


def int_from_value(value: object, context: str, warnings: list[str], default: int = 0) -> int:
    """
    Convert a value to an integer.
    """

    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    if value is None:
        warn(warnings, "{} missing; using {}".format(context, default))
    else:
        warn(warnings, "{} should be an integer; using {}".format(context, default))
    return default


def bool_from_value(value: object, context: str, warnings: list[str]) -> bool:
    """
    Convert a value to a boolean.
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lower = value.strip().lower()
        if lower in ("true", "yes", "1"):
            return True
        if lower in ("false", "no", "0"):
            return False
    if value is None:
        warn(warnings, "{} missing; using false".format(context))
    else:
        warn(warnings, "{} should be a boolean; using false".format(context))
    return False


def warn_unknown_keys(
    mapping: dict[str, object], expected: set[str], context: str, warnings: list[str]
) -> None:
    """
    Warn about keys that are not recognised.
    """

    for key in sorted(mapping):
        if key not in expected:
            warn(warnings, "{} has unexpected field {!r}".format(context, key))


def warn_missing_keys(
    mapping: dict[str, object], expected: set[str], context: str, warnings: list[str]
) -> None:
    """
    Warn about expected keys that are not present.
    """

    for key in sorted(expected):
        if key not in mapping:
            warn(warnings, "{} is missing expected field {!r}".format(context, key))


def load_attachment_bytes(
    mapping: dict[str, object],
    inline_key: str,
    file_key: str,
    base_dir: Path,
    context: str,
    warnings: list[str],
    text_mode: bool,
) -> bytes:
    """
    Load attachment content from inline YAML or a detached file.
    """

    if file_key in mapping:
        filename = mapping[file_key]
        if not isinstance(filename, str) or filename == "":
            warn(warnings, "{}.{} should name a file; using empty content".format(context, file_key))
            return b""
        path = base_dir.joinpath(filename)
        try:
            return path.read_bytes()
        except OSError as exc:
            warn(warnings, "{}.{} could not be read from {}: {}".format(context, file_key, path, exc))
            return b""

    if inline_key not in mapping:
        warn(warnings, "{}.{} missing; using empty content".format(context, inline_key))
        return b""

    value = mapping[inline_key]
    if text_mode:
        return encode_attachment_text(value, "{}.{}".format(context, inline_key), warnings)

    if not isinstance(value, str):
        warn(warnings, "{}.{} should be base64 text; using empty content".format(context, inline_key))
        return b""
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        warn(warnings, "{}.{} is not valid base64: {}".format(context, inline_key, exc))
        return b""


def serialise_registration(
    registration: dict[str, object], index: int, base_dir: Path, warnings: list[str]
) -> bytes | None:
    """
    Serialise one registration entry from YAML.
    """

    if len(registration) != 1:
        warn(warnings, "Registration {} should contain exactly one object type".format(index))
        return None

    raw_name, values = next(iter(registration.items()))
    object_name = OBJECT_ALIASES.get(raw_name)
    if object_name is None:
        warn(warnings, "Registration {} has unknown type {!r}; skipping".format(index, raw_name))
        return None
    if not isinstance(values, dict):
        warn(warnings, "Registration {} {} content should be a mapping; skipping".format(index, object_name))
        return None

    context = "Registration {} {}".format(index, object_name)

    if object_name == "SWIChunk":
        expected = {"Prefix", "Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = (
            encode_text_field(values.get("Prefix"), 20, "{}.Prefix".format(context), warnings)
            + encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
        )
    elif object_name == "MessageBlock":
        expected = {"Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
    elif object_name == "Reservation":
        expected = {"Type", "Text"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = (
            encode_text_field(values.get("Text"), 40, "{}.Text".format(context), warnings)
            + encode_text_field(values.get("Type"), 20, "{}.Type".format(context), warnings)
        )
    elif object_name == "Filetype":
        expected = {
            "ApplicationName",
            "Name",
            "DoubleClicking",
            "Sprite",
            "SpriteFile",
            "ProductDescription",
            "ProductDescriptionFile",
            "FormatDescription",
            "FormatDescriptionFile",
        }
        warn_unknown_keys(
            values,
            expected,
            context,
            warnings,
        )
        warn_missing_keys(values, {"ApplicationName", "Name", "DoubleClicking"}, context, warnings)
        if "Sprite" in values and "SpriteFile" in values:
            warn(warnings, "{} has both Sprite and SpriteFile; using SpriteFile".format(context))
        if "ProductDescription" in values and "ProductDescriptionFile" in values:
            warn(warnings, "{} has both ProductDescription and ProductDescriptionFile; using ProductDescriptionFile".format(context))
        if "FormatDescription" in values and "FormatDescriptionFile" in values:
            warn(warnings, "{} has both FormatDescription and FormatDescriptionFile; using FormatDescriptionFile".format(context))

        sprite = load_attachment_bytes(
            values, "Sprite", "SpriteFile", base_dir, context, warnings, text_mode=False
        )
        product = load_attachment_bytes(
            values,
            "ProductDescription",
            "ProductDescriptionFile",
            base_dir,
            context,
            warnings,
            text_mode=True,
        )
        format_desc = load_attachment_bytes(
            values,
            "FormatDescription",
            "FormatDescriptionFile",
            base_dir,
            context,
            warnings,
            text_mode=True,
        )

        payload = b"".join(
            [
                encode_text_field(values.get("ApplicationName"), 12, "{}.ApplicationName".format(context), warnings),
                encode_text_field(values.get("Name"), 9, "{}.Name".format(context), warnings),
                struct.pack(
                    "<i",
                    1 if bool_from_value(values.get("DoubleClicking"), "{}.DoubleClicking".format(context), warnings) else 0,
                ),
                struct.pack("<i", len(sprite)),
                sprite,
                struct.pack("<i", len(product)),
                product,
                struct.pack("<i", len(format_desc)),
                format_desc,
            ]
        )
    elif object_name == "ErrorBlock":
        expected = {"Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
    elif object_name == "Podule":
        expected = {"AllocateManufacturer", "ManufacturerId", "PoduleName", "Description"}
        warn_unknown_keys(
            values,
            expected,
            context,
            warnings,
        )
        warn_missing_keys(values, expected, context, warnings)
        allocate_manufacturer = bool_from_value(
            values.get("AllocateManufacturer"), "{}.AllocateManufacturer".format(context), warnings
        )
        manufacturer_id = int_from_value(
            values.get("ManufacturerId"), "{}.ManufacturerId".format(context), warnings
        )
        if not allocate_manufacturer and manufacturer_id == 0:
            warn(warnings, "{}.ManufacturerId is expected when AllocateManufacturer is false".format(context))
        payload = b"".join(
            [
                struct.pack("<i", 1 if allocate_manufacturer else 0),
                struct.pack("<i", manufacturer_id),
                encode_text_field(values.get("PoduleName"), 20, "{}.PoduleName".format(context), warnings),
                encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings),
            ]
        )
    elif object_name == "DrawTagBlock":
        expected = {"Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
    elif object_name == "DrawObjectBlock":
        expected = {"Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
    elif object_name == "FilingSystem":
        expected = {"Name", "Selector", "Select"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, {"Name"}, context, warnings)
        if "Selector" not in values and "Select" not in values:
            warn(warnings, "{} is missing expected field 'Selector'".format(context))
        selector = values.get("Selector", values.get("Select"))
        if "Select" in values and "Selector" not in values:
            warn(warnings, "{}.Select is accepted for compatibility; prefer Selector".format(context))
        payload = (
            encode_text_field(values.get("Name"), 20, "{}.Name".format(context), warnings)
            + encode_text_field(selector, 20, "{}.Selector".format(context), warnings)
        )
    elif object_name == "ServiceBlock":
        expected = {"Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
    elif object_name == "Device":
        expected = {"Name", "Description"}
        warn_unknown_keys(values, expected, context, warnings)
        warn_missing_keys(values, expected, context, warnings)
        payload = (
            encode_text_field(values.get("Name"), 20, "{}.Name".format(context), warnings)
            + encode_text_field(values.get("Description"), 100, "{}.Description".format(context), warnings)
        )
    else:
        warn(warnings, "Registration {} type {!r} is not supported".format(index, object_name))
        return None

    return OBJECT_HEADER_STRUCT.pack(OBJECT_NAME_TO_ID[object_name], len(payload)) + payload


def parse_format_version(value: object, warnings: list[str]) -> int:
    """
    Parse the YAML format version field.
    """

    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"\d+\.\d{2}", text):
            whole, frac = text.split(".", 1)
            return int(whole) * 100 + int(frac)
        if re.fullmatch(r"\d+", text):
            return int(text)
    if value is None:
        warn(warnings, "FormatVersion missing; using 1.00")
    else:
        warn(warnings, "FormatVersion is invalid; using 1.00")
    return 100


def load_yaml_description(source: Path) -> tuple[dict[str, object], Path, list[str]]:
    """
    Load a YAML description from a file or extracted directory.
    """

    if source.is_dir():
        yaml_path = source.joinpath("Allocation.yaml")
        base_dir = source
    else:
        yaml_path = source
        base_dir = source.parent

    text = yaml_path.read_text(encoding="utf-8")
    parser = SimpleYamlParser(text)
    data, warnings = parser.parse()
    return data, base_dir, warnings


def build_allocate_binary(source: Path) -> tuple[bytes, list[str]]:
    """
    Build a binary Allocate request file from YAML.
    """

    data, base_dir, warnings = load_yaml_description(source)
    if not isinstance(data, dict):
        raise ParseError("Description file did not contain a top-level mapping")

    warn_unknown_keys(data, TOP_LEVEL_KEYS, "Top level", warnings)

    schema_version = data.get("SchemaVersion")
    if schema_version is None:
        warn(warnings, "SchemaVersion missing; assuming version 1")
    elif schema_version != 1:
        warn(warnings, "SchemaVersion is {!r}; version 1 is expected".format(schema_version))

    version = parse_format_version(data.get("FormatVersion"), warnings)

    developer = data.get("Developer")
    if developer is None:
        warn(warnings, "Developer block missing; using blank details")
        developer = {}
    elif not isinstance(developer, dict):
        warn(warnings, "Developer block should be a mapping; using blank details")
        developer = {}

    developer_expected = {label for label, _, _ in DEVELOPER_FIELDS}
    warn_unknown_keys(developer, developer_expected, "Developer", warnings)
    warn_missing_keys(developer, developer_expected, "Developer", warnings)

    details = b"".join(
        encode_text_field(developer.get(label), size, "Developer.{}".format(label), warnings)
        for label, _, size in DEVELOPER_FIELDS
    )

    registrations = data.get("Registrations")
    if registrations is None:
        warn(warnings, "Registrations missing; creating an empty request")
        registrations = []
    elif not isinstance(registrations, list):
        warn(warnings, "Registrations should be a sequence; creating an empty request")
        registrations = []

    object_data: list[bytes] = []
    for index, registration in enumerate(registrations, start=1):
        if not isinstance(registration, dict):
            warn(warnings, "Registration {} should be a mapping; skipping".format(index))
            continue
        object_bytes = serialise_registration(registration, index, base_dir, warnings)
        if object_bytes is not None:
            object_data.append(object_bytes)

    header = HEADER_STRUCT.pack(MAGIC, version, len(object_data))
    return header + details + b"".join(object_data), warnings


def display_file(parsed: dict[str, object]) -> None:
    """
    Display a parsed Allocate file.
    """

    print("File: {}".format(parsed['path']))
    print("Format version: {} ({})".format(format_version(parsed['version']), parsed['version']))
    print("Objects: {}".format(parsed['object_count']))
    if parsed["trailing_bytes"]:
        print("Trailing bytes: {}".format(parsed['trailing_bytes']))
    print()

    print("Developer details:")
    details = parsed["details"]
    labels = [
        ("Name", "name"),
        ("Company", "company"),
        ("Developer number", "developer_number"),
        ("Address 1", "address1"),
        ("Address 2", "address2"),
        ("Address 3", "address3"),
        ("Address 4", "address4"),
        ("Phone", "phone"),
        ("Fax", "fax"),
        ("Email", "email"),
    ]
    for label, key in labels:
        print_key_value(label, details[key], indent="  ")
    print()

    print("Objects:")
    for obj in parsed["objects"]:
        print("  {}. {} (id={}, size={})".format(obj['index'], obj['name'], obj['id'], obj['size']))
        values = obj["values"]
        if obj["id"] == 3:
            print_key_value("Application name", values["application_name"], indent="     ")
            print_key_value("Filetype name", values["filetype_name"], indent="     ")
            print_key_value(
                "Double clicking",
                "yes" if values["double_clicking"] else "no",
                indent="     ",
            )
            for attachment in values["attachments"]:
                print(
                    "     {}: attached ({} bytes)".format(attachment.kind.title(), attachment.size)
                )
            continue

        for key, value in values.items():
            label = key.replace("_", " ").capitalize()
            if key == "allocate_manufacturer":
                value = "yes" if value else "no"
            print_key_value(label, value, indent="     ")


def print_warnings(warnings: list[str]) -> None:
    """
    Emit warnings to stderr.
    """

    for message in warnings:
        print("warning: {}".format(message), file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command line parser.
    """

    parser = argparse.ArgumentParser(
        description="Display or convert Allocate request files."
    )
    parser.add_argument(
        "file",
        type=Path,
        help="Allocate request file to parse, or YAML file/directory to create from",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="Extract the request to a YAML description file format",
    )
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create a binary Allocate request from a YAML description file or directory",
    )
    parser.add_argument(
        "--extract-files",
        type=Path,
        metavar="DIRECTORY",
        help="Extract the request to Allocation.yaml and detached files in DIRECTORY",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write extracted YAML to this file instead of stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Run the command line tool.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.extract_files is not None:
        args.extract = True
    if args.extract and args.create:
        parser.error("--extract and --create cannot be used together")
    if args.extract_files is not None and args.output is not None:
        parser.error("--output cannot be used with --extract-files")
    if args.output is not None and not (args.extract or args.create):
        parser.error("--output requires --extract or --create")

    if args.create:
        try:
            binary, warnings = build_allocate_binary(args.file)
        except (OSError, ParseError) as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 1

        print_warnings(warnings)
        if args.output is None:
            sys.stdout.buffer.write(binary)
        else:
            try:
                args.output.write_bytes(binary)
            except OSError as exc:
                print("error: {}".format(exc), file=sys.stderr)
                return 1
        return 0

    try:
        parsed = parse_allocate_file(args.file)
    except (OSError, ParseError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    if args.extract_files is not None:
        try:
            write_extract_files(parsed, args.extract_files)
        except OSError as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 1
        return 0

    if args.extract:
        yaml_text, _ = build_yaml(parsed)
        if args.output is None:
            sys.stdout.write(yaml_text)
        else:
            try:
                args.output.write_text(yaml_text, encoding="utf-8")
            except OSError as exc:
                print("error: {}".format(exc), file=sys.stderr)
                return 1
        return 0

    display_file(parsed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
