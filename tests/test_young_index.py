"""RDAP registration-date supply for the young_index signal (network-free)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from features import PageFeatures, extract_features
from fetch import FetchResult
from scorer import Scorer
from whois_rdap import RdapInfo


def _browser() -> FetchResult:
    return FetchResult(
        url="https://example.com/",
        status=200,
        final_url="https://example.com/",
        chain=[(200, "https://example.com/")],
        body="<html><title>Example</title><body>Welcome</body></html>",
    )


def _rdap(registration_date: str, *, ok: bool = True) -> RdapInfo:
    return RdapInfo(domain="example.com", ok=ok, registration_date=registration_date)


def test_from_json_parses_first_registration_event():
    info = RdapInfo.from_json(
        "example.com",
        {
            "events": [
                {"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2025-02-03T04:05:06Z"},
                {"eventAction": "registration", "eventDate": "2025-03-04T00:00:00Z"},
            ]
        },
    )
    assert info.registration_date == "2025-02-03T04:05:06Z"


def test_young_index_is_true_at_30_days():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = (now - timedelta(days=30)).isoformat()
    features = extract_features("example.com", _browser(), rdap=_rdap(registered), now=now)
    assert features.young_index is True


def test_young_index_is_false_at_91_days():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = (now - timedelta(days=91)).isoformat()
    features = extract_features("example.com", _browser(), rdap=_rdap(registered), now=now)
    assert features.young_index is False


def test_young_index_boundary_is_inclusive_90_days():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = now - timedelta(days=90)
    features = extract_features(
        "example.com", _browser(), rdap=_rdap(registered.isoformat()), now=now
    )
    assert features.young_index is True


def test_young_index_is_false_at_90_days_plus_one_second():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = now - timedelta(days=90, seconds=1)
    features = extract_features(
        "example.com", _browser(), rdap=_rdap(registered.isoformat()), now=now
    )
    assert features.young_index is False


def test_young_index_is_false_at_90_days_23_hours_59_minutes():
    """`.days` の切り捨てで 90 日に見えるケースを false にする (README: 90 日以内)。"""
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = now - timedelta(days=90, hours=23, minutes=59)
    features = extract_features(
        "example.com", _browser(), rdap=_rdap(registered.isoformat()), now=now
    )
    assert features.young_index is False


def test_young_index_is_true_at_89_days_23_hours_59_minutes():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = now - timedelta(days=89, hours=23, minutes=59)
    features = extract_features(
        "example.com", _browser(), rdap=_rdap(registered.isoformat()), now=now
    )
    assert features.young_index is True


def test_young_index_is_false_without_events():
    info = RdapInfo.from_json("example.com", {})
    features = extract_features(
        "example.com", _browser(), rdap=info, now=datetime(2026, 10, 20, tzinfo=UTC)
    )
    assert features.young_index is False


def test_young_index_is_false_when_rdap_failed():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = (now - timedelta(days=1)).isoformat()
    features = extract_features(
        "example.com", _browser(), rdap=_rdap(registered, ok=False), now=now
    )
    assert features.young_index is False


def test_young_index_is_false_for_future_registration_date():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = (now + timedelta(days=1)).isoformat()
    features = extract_features("example.com", _browser(), rdap=_rdap(registered), now=now)
    assert features.young_index is False


def test_young_index_is_false_for_garbage_registration_date():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    features = extract_features("example.com", _browser(), rdap=_rdap("not-a-date"), now=now)
    assert features.young_index is False


def test_young_index_is_serialized():
    now = datetime(2026, 10, 20, tzinfo=UTC)
    registered = (now - timedelta(days=30)).isoformat()
    features = extract_features("example.com", _browser(), rdap=_rdap(registered), now=now)
    assert features.to_dict()["young_index"] is True


def test_scorer_adds_young_index_weight_exactly_once():
    features = PageFeatures(domain="example.com", young_index=True)
    score = Scorer().score(features)
    assert score.total == 5
    assert score.reasons == {"young_index": 5}
