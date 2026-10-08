from cypher.ingest.parsers.auth import AuthLogParser
from cypher.ingest.parsers.syslog import SyslogParser
from cypher.ingest.parsers.webaccess import WebAccessParser
from cypher.ingest.parsers.windows_security import WindowsSecurityParser

# Keys match the field names in settings.SourcesSettings.
PARSERS_BY_SOURCE = {
    "auth_log": AuthLogParser,
    "syslog": SyslogParser,
    "web_access_log": WebAccessParser,
    "windows_security_log": WindowsSecurityParser,
}

__all__ = [
    "AuthLogParser", "SyslogParser", "WebAccessParser",
    "WindowsSecurityParser", "PARSERS_BY_SOURCE",
]
