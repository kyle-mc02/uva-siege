"""Parser registry. One plugin per tool; each emits a `ScanResult`.

A parser is a callable `(raw: str, source_file: str) -> ScanResult`. Register
it under the tool name so the import endpoint (Phase 1) and future auto-detect
can look it up. Keeping this a plain dict avoids import-time magic; add new
tools by importing their module and calling `register`.
"""

from __future__ import annotations

from typing import Callable

from ..models import ScanResult

Parser = Callable[[str, str], ScanResult]

_REGISTRY: dict[str, Parser] = {}


def register(tool: str, parser: Parser) -> None:
    _REGISTRY[tool] = parser


def get(tool: str) -> Parser:
    try:
        return _REGISTRY[tool]
    except KeyError:
        raise KeyError(f"no parser registered for tool {tool!r}; have {sorted(_REGISTRY)}")


def available() -> list[str]:
    return sorted(_REGISTRY)


# Register the built-in parsers on import.
from . import nmap as _nmap  # noqa: E402  (import after registry defined)

register("nmap", _nmap.parse)
