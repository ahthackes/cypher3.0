"""Offline GeoIP lookups against a local MaxMind GeoLite2-City database.

Needs the free `maxminddb` package and a GeoLite2-City.mmdb file placed
at geo.geolite_db (download once, from an account you register for
yourself — MaxMind's license means we can't bundle the database, only
the code that reads it). Looks up entirely offline once the file exists.

If the database file isn't present, lookups return None and the
dashboard simply omits the map pin for that IP — this is optional
enrichment, not something detection depends on.
"""
from __future__ import annotations

from pathlib import Path


class GeoIPLookup:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._reader = None
        if self.db_path.exists():
            try:
                import maxminddb
                self._reader = maxminddb.open_database(str(self.db_path))
            except ImportError:
                pass  # optional dependency not installed — degrade gracefully

    def lookup(self, ip: str) -> dict | None:
        if self._reader is None:
            return None
        try:
            result = self._reader.get(ip)
        except ValueError:
            return None
        if not result:
            return None
        return {
            "country": result.get("country", {}).get("names", {}).get("en"),
            "city": result.get("city", {}).get("names", {}).get("en"),
            "lat": result.get("location", {}).get("latitude"),
            "lon": result.get("location", {}).get("longitude"),
        }

    def close(self) -> None:
        if self._reader:
            self._reader.close()
