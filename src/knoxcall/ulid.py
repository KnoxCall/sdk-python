"""ULID generator for idempotency keys. 26-char Crockford base32."""

from __future__ import annotations
import os
import time

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    time_part = ""
    t = now_ms
    for _ in range(10):
        mod = t % 32
        time_part = _B32[mod] + time_part
        t //= 32

    rand = os.urandom(10)
    rand_part = ""
    bit_buf = 0
    bits = 0
    for byte in rand:
        bit_buf = (bit_buf << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            rand_part += _B32[(bit_buf >> bits) & 0x1F]
    if bits > 0:
        rand_part += _B32[(bit_buf << (5 - bits)) & 0x1F]
    return (time_part + rand_part)[:26]
