from cypher.respond.backends.base import FirewallBackend
from cypher.respond.backends.iptables import IptablesBackend
from cypher.respond.backends.nftables import NftablesBackend
from cypher.respond.backends.ufw import UfwBackend
from cypher.respond.backends.windows_firewall import WindowsFirewallBackend

BACKENDS: dict[str, type[FirewallBackend]] = {
    "nftables": NftablesBackend,
    "iptables": IptablesBackend,
    "ufw": UfwBackend,
    "windows_firewall": WindowsFirewallBackend,
}


def get_backend(name: str) -> FirewallBackend:
    cls = BACKENDS.get(name)
    if cls is None:
        raise ValueError(f"Unknown firewall backend '{name}'. Options: {list(BACKENDS)}")
    return cls()
