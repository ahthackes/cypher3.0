from datetime import datetime

from cypher.features.templating import template_id, templatize
from cypher.features.vectorizer import FEATURE_NAMES, FeatureVectorizer
from cypher.models import Event, EventType


def test_templatize_masks_ips_and_numbers():
    msg = "Failed password for admin from 203.0.113.5 port 50001 ssh2"
    template = templatize(msg)
    assert "203.0.113.5" not in template
    assert "50001" not in template
    assert "<IP>" in template


def test_template_id_is_stable_across_different_ips():
    a = "Failed password for admin from 203.0.113.5 port 50001 ssh2"
    b = "Failed password for admin from 198.51.100.9 port 60002 ssh2"
    assert template_id(a) == template_id(b)


def test_vectorizer_output_shape_matches_feature_names():
    vec = FeatureVectorizer()
    event = Event(
        timestamp=datetime(2026, 1, 1, 12, 0, 0), src_ip="203.0.113.5",
        event_type=EventType.AUTH_FAILURE, message="Failed password for admin from 203.0.113.5 port 50001 ssh2",
    )
    result = vec.transform(event)
    assert result.shape == (len(FEATURE_NAMES),)


def test_vectorizer_activity_count_increases_with_repeats():
    vec = FeatureVectorizer()
    ts = datetime(2026, 1, 1, 12, 0, 0)
    event = Event(timestamp=ts, src_ip="203.0.113.5", message="Failed password from 203.0.113.5")
    first = vec.transform(event)
    second = vec.transform(event)
    # index 4 is events_last_60s
    assert second[4] > first[4]
