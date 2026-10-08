from cypher.ingest.normalizer import normalize
from cypher.models import Event


def test_normalize_valid_ip_passes_through():
    e = Event(src_ip="203.0.113.5", message="hello")
    result = normalize(e)
    assert result is not None
    assert result.src_ip == "203.0.113.5"


def test_normalize_strips_ipv6_mapped_prefix():
    e = Event(src_ip="::ffff:10.0.0.5", message="hello")
    result = normalize(e)
    assert result.src_ip == "10.0.0.5"


def test_normalize_drops_invalid_ip():
    e = Event(src_ip="not-an-ip", message="hello")
    result = normalize(e)
    assert result.src_ip is None


def test_normalize_drops_empty_message():
    e = Event(message="")
    assert normalize(e) is None
