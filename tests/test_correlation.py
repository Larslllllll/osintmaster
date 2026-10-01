from osintmaster.core.correlation import correlate, correlate_findings, label_for
from osintmaster.core.models import Finding, FindingStatus, Profile


def test_same_username_is_weak_evidence():
    left = Finding("A", "alex", "https://a.example/alex", FindingStatus.CONFIRMED)
    right = Finding("B", "alex", "https://b.example/alex", FindingStatus.POSSIBLE)
    result = correlate(left, right)
    assert result.score == 7
    assert result.label == "weak"
    assert [item.type for item in result.evidence] == ["exact_username"]


def test_conflicting_public_claims_are_negative_evidence():
    left = Finding(
        "A",
        "alex",
        "https://a.example/alex",
        FindingStatus.CONFIRMED,
        profile=Profile(display_name="Alex Smith", location="Berlin"),
    )
    right = Finding(
        "B",
        "alex",
        "https://b.example/alex",
        FindingStatus.CONFIRMED,
        profile=Profile(display_name="Morgan Taylor", location="Tokyo"),
    )
    result = correlate(left, right)
    assert result.score == 1
    assert {item.type for item in result.evidence} == {
        "exact_username",
        "conflicting_name_claims",
        "conflicting_location_claims",
    }


def test_correlation_explains_aggregate_score():
    profile = Profile(
        display_name="Alex Smith",
        bio="Researcher in public source analysis",
        links=["https://example.org/about?utm_source=profile"],
    )
    left = Finding(
        "A", "alexsmith", "https://a.example/a", FindingStatus.CONFIRMED, profile=profile
    )
    right = Finding(
        "B",
        "alexsmith",
        "https://b.example/b",
        FindingStatus.CONFIRMED,
        profile=Profile(
            display_name="Alex Smith",
            bio="Researcher in public source analysis",
            links=["https://example.org/about"],
        ),
    )
    result = correlate(left, right)
    assert result.score == 50
    assert result.label == "possible"
    assert result.score == sum(item.weight for item in result.evidence)
    assert len(correlate_findings([left, right])) == 1


def test_labels_and_inactive_findings():
    assert [label_for(score) for score in (0, 29, 30, 60, 80, 100)] == [
        "weak",
        "weak",
        "possible",
        "probable",
        "strong",
        "strong",
    ]
    missing = Finding("A", "alex", "https://a.example", FindingStatus.NOT_FOUND)
    found = Finding("B", "alex", "https://b.example", FindingStatus.CONFIRMED)
    assert correlate_findings([missing, found]) == []


def test_wide_empty_profiles_do_not_create_pairwise_identity_links():
    findings = [
        Finding(str(index), "alex", f"https://site{index}.example/alex", FindingStatus.PROBABLE)
        for index in range(121)
    ]
    assert correlate_findings(findings) == []
