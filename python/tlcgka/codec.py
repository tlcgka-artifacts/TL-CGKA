"""Canonical encoding and decoding of protocol messages."""
import struct


class ProtocolError(ValueError):
    pass


MAX_WIRE = 64 * 1024 * 1024


def pack(value):
    if value is None:
        return b"n"
    if isinstance(value, bool):
        return b"t" if value else b"f"
    if isinstance(value, int):
        if not 0 <= value < 2**64:
            raise ProtocolError("wire integer outside uint64")
        return b"i" + struct.pack(">Q", value)
    if isinstance(value, bytes):
        return b"b" + struct.pack(">I", len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return b"s" + struct.pack(">I", len(data)) + data
    if isinstance(value, (tuple, list)):
        return b"l" + struct.pack(">I", len(value)) + b"".join(pack(v) for v in value)
    raise TypeError(f"unsupported wire type: {type(value).__name__}")


def unpack(data):
    if not isinstance(data, bytes) or len(data) > MAX_WIRE:
        raise ProtocolError("invalid wire buffer")

    def read(pos, depth):
        if depth > 32 or pos >= len(data):
            raise ProtocolError("truncated or too deeply nested wire")
        tag, pos = data[pos:pos + 1], pos + 1
        if tag in (b"n", b"t", b"f"):
            return {b"n": None, b"t": True, b"f": False}[tag], pos
        if tag == b"i":
            if pos + 8 > len(data):
                raise ProtocolError("truncated integer")
            return struct.unpack(">Q", data[pos:pos + 8])[0], pos + 8
        if tag not in (b"b", b"s", b"l") or pos + 4 > len(data):
            raise ProtocolError("invalid wire tag or length")
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        if length > len(data) - pos:
            raise ProtocolError("invalid wire length")
        if tag == b"l":
            items = []
            for _ in range(length):
                v, pos = read(pos, depth + 1)
                items.append(v)
            return tuple(items), pos
        value, pos = data[pos:pos + length], pos + length
        if tag == b"s":
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("invalid UTF-8") from exc
        return value, pos

    value, end = read(0, 0)
    if end != len(data):
        raise ProtocolError("trailing wire bytes")
    return value


def require(condition, message):
    if not condition:
        raise ProtocolError(message)
