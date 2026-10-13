"""Per-engagement bearer-token auth (HANDOFF.md security must-do #4).

One shared secret per engagement, Jupyter-style: generated on first run, stored
in a 0600 file next to the DB so it survives restarts and the startup banner can
print a ready-to-click URL. This is deliberately not multi-user — the model is
"one server per engagement, trusted team". Per-operator identity is carried by
the free-text `actor`/`added_by` fields, not by auth.

The token gates every /api/* and /ws request. The static SPA shell and /wall
HTML are public (they hold no data); the browser pulls ?token= from the URL
once, stores it, and sends it as a Bearer header thereafter.

TODO(phase 3): optional OIDC / per-user accounts if an engagement needs real
multi-tenant separation.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path


def load_or_create_token(db_path: str | Path) -> str:
    """Return the engagement token, creating a 0600 token file if absent."""
    token_file = Path(str(db_path) + ".token")
    if token_file.exists():
        tok = token_file.read_text().strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(32)
    # Create with 0600 from the start (don't briefly expose a world-readable secret).
    fd = os.open(str(token_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok + "\n")
    return tok


def token_matches(expected: str, presented: str | None) -> bool:
    """Constant-time comparison; tolerates a 'Bearer ' prefix."""
    if not presented:
        return False
    if presented.startswith("Bearer "):
        presented = presented[len("Bearer ") :]
    return hmac.compare_digest(expected, presented)
