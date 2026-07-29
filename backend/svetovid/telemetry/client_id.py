"""Anonymous installation identifier.

A single UUID v4 persisted at ``~/.svetovid/client_id.txt``. It names an
*installation*, not a person — there is no link to user identity, hostname,
or account. Used as the ``client_id`` field on every telemetry record so the
collection server can tell installations apart without deanonymizing anyone.

The file is created on first call and reused forever after. It is plain text
(one line, no whitespace beyond a trailing newline) so it survives backups and
is easy to inspect / delete by hand.
"""

from __future__ import annotations

import uuid

from ..config import APP_DIR

CLIENT_ID_FILE = APP_DIR / "client_id.txt"


def get_client_id() -> str:
    """Return this installation's anonymous UUID, creating it on first run.

    Always returns a canonical lowercase UUID v4 string (32 hex digits + dashes).
    The value is stable across calls and process restarts.
    """
    APP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        raw = CLIENT_ID_FILE.read_text().strip()
        # Validate it really is a UUID — if someone hand-edited garbage in,
        # regenerate rather than ship malformed data.
        return str(uuid.UUID(raw))
    except (FileNotFoundError, ValueError):
        new_id = str(uuid.uuid4())
        CLIENT_ID_FILE.write_text(new_id + "\n")
        try:
            # chmod 600 — it's identifying data even if anonymous.
            CLIENT_ID_FILE.chmod(0o600)
        except OSError:
            pass
        return new_id
