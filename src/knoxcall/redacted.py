"""Opaque wrapper for sensitive values — see redacted.ts in the JS SDK."""

from __future__ import annotations
from typing import Generic, TypeVar

T = TypeVar("T")


class Redacted(Generic[T]):
    """Wraps a sensitive value so accidental logging can't leak it.

    repr / str / __format__ all return ``[REDACTED]``. Use ``.expose()`` only
    at the moment of HTTP header construction.
    """

    __slots__ = ("_value",)

    def __init__(self, value: T) -> None:
        self._value = value

    def expose(self) -> T:
        return self._value

    def __repr__(self) -> str:
        return "[REDACTED]"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __format__(self, _spec: str) -> str:
        return "[REDACTED]"
