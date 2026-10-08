"""The responder listens on a loopback TCP socket (127.0.0.1), which
any local process can technically connect to — on both Linux and
Windows, "only localhost can connect" is not "only Cypher can connect".
This module is what closes that gap: a random token, generated once and
written to disk, that every IPC request must include. The socket
accepts the connection; `ResponderService` (via the request handler)
rejects the request if the token doesn't match.

File permissions (the token must be readable by the unprivileged
ingest/API processes, but by nobody else):

  Linux    the responder (root) creates the file. If a `cypher` group
           exists (scripts/install.sh creates it) the file is chgrp'd to
           it and set 0640, so exactly the root user and the `cypher`
           group can read it. With no such group it falls back to 0600.
  Windows  os.chmod has no real effect. deploy/windows/install.ps1 sets
           an ACL on the data directory instead (SYSTEM, Administrators
           and the API's service account only) — the Windows-native
           equivalent.
"""
from __future__ import annotations

import secrets
import stat
from pathlib import Path

from cypher.platform_utils import IS_WINDOWS

_TOKEN_BYTES = 32
_SHARED_GROUP = "cypher"


def get_or_create_token(path: str | Path) -> str:
    token_path = Path(path)
    if token_path.exists():
        return token_path.read_text().strip()

    token_path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(_TOKEN_BYTES)
    token_path.write_text(token)
    if not IS_WINDOWS:
        _restrict_posix_permissions(token_path)
    return token


def _restrict_posix_permissions(path: Path) -> None:
    import grp
    import os

    try:
        gid = grp.getgrnam(_SHARED_GROUP).gr_gid
    except KeyError:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600: no shared group configured
        return
    try:
        os.chown(path, -1, gid)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0640
    except PermissionError:
        # Not root, so can't hand the file to another group: stay owner-only
        # rather than leave it more widely readable than intended.
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
