# .deb packaging (Phase 6)

Planned layout for a `dpkg-deb`-built package:

- `/opt/cypher/` — application code + venv
- `/etc/cypher/` — config/cypher.toml, allowlist.toml, rules.d/ (symlinked or copied from /opt/cypher/config)
- `/lib/systemd/system/` — the three unit files in deploy/systemd/
- postinst: creates the `cypher` system user/group, `/run/cypher`, runs `cypher train` if sample data exists

Not yet built — this is a placeholder for the Phase 6 packaging work
described in the project plan (docs/architecture.md).
