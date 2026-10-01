"""Explainable pairwise correlation of public profile claims."""

from __future__ import annotations

from itertools import combinations

from osintmaster.core.models import Correlation, Evidence, Finding, FindingStatus
from osintmaster.core.normalization import normalize_text, normalize_url, similarity

ACTIVE = {FindingStatus.CONFIRMED, FindingStatus.PROBABLE, FindingStatus.POSSIBLE}
LABEL_SIGNALS = {
    "exact_username",
    "similar_username",
    "identical_display_name",
    "similar_display_name",
}
LABEL_SIGNAL_CAP = 18
MIN_REPORTED_SCORE = 30


def label_for(score: int) -> str:
    if score >= 80:
        return "strong"
    if score >= 60:
        return "probable"
    if score >= 30:
        return "possible"
    return "weak"


def _normalized_links(finding: Finding) -> set[str]:
    result = set()
    for link in finding.profile.links:
        try:
            result.add(normalize_url(link))
        except ValueError:
            continue
    return result


def correlate(left: Finding, right: Finding) -> Correlation:
    evidence: list[Evidence] = []
    quality = min(
        {FindingStatus.CONFIRMED: 1.0, FindingStatus.PROBABLE: 0.85, FindingStatus.POSSIBLE: 0.7}[
            left.status
        ],
        {FindingStatus.CONFIRMED: 1.0, FindingStatus.PROBABLE: 0.85, FindingStatus.POSSIBLE: 0.7}[
            right.status
        ],
    )

    def add(kind: str, value: str, weight: int) -> None:
        adjusted = round(weight * quality) if weight > 0 else weight
        evidence.append(Evidence(kind, value, adjusted, f"{left.url} ↔ {right.url}"))

    if left.username.casefold() == right.username.casefold():
        add("exact_username", left.username, 10)
    elif similarity(left.username, right.username) >= 0.8:
        add("similar_username", f"{left.username} / {right.username}", 4)

    if left.profile.display_name and right.profile.display_name:
        score = similarity(left.profile.display_name, right.profile.display_name)
        if score == 1:
            add("identical_display_name", left.profile.display_name, 15)
        elif score >= 0.85:
            add("similar_display_name", f"similarity {score:.0%}", 8)
        elif (
            score < 0.3
            and len(left.profile.display_name.split()) >= 2
            and len(right.profile.display_name.split()) >= 2
        ):
            add("conflicting_name_claims", "Different public display names", -5)

    if left.profile.bio and right.profile.bio:
        a, b = normalize_text(left.profile.bio), normalize_text(right.profile.bio)
        if len(a) >= 20 and len(b) >= 20:
            score = similarity(a, b)
            if score == 1:
                add("identical_bio", "Same public biography text", 12)
            elif score >= 0.85:
                add("similar_bio", f"similarity {score:.0%}", 8)

    common = _normalized_links(left) & _normalized_links(right)
    if common:
        add("same_external_url", sorted(common)[0], 20)

    if left.profile.image_url and right.profile.image_url:
        try:
            if normalize_url(left.profile.image_url) == normalize_url(right.profile.image_url):
                add("same_profile_image_url", "Same public image URL (image content unverified)", 8)
        except ValueError:
            pass

    if (
        left.profile.image_hash
        and right.profile.image_hash
        and (left.profile.image_hash == right.profile.image_hash)
    ):
        add("same_profile_image_hash", "Same externally supplied image hash", 25)

    if (
        left.profile.location
        and right.profile.location
        and (normalize_text(left.profile.location) == normalize_text(right.profile.location))
    ):
        add("same_location_claim", left.profile.location, 5)
    elif (
        left.profile.location
        and right.profile.location
        and similarity(left.profile.location, right.profile.location) < 0.3
    ):
        add("conflicting_location_claims", "Different public location claims", -4)

    # Handles and display names often derive from the same chosen label.
    # Count at most 18 points from that related group, while retaining each reason.
    label_total = 0
    adjusted_evidence: list[Evidence] = []
    for item in evidence:
        if item.type in LABEL_SIGNALS and item.weight > 0:
            kept = min(item.weight, max(0, LABEL_SIGNAL_CAP - label_total))
            label_total += kept
            adjusted_evidence.append(Evidence(item.type, item.value, kept, item.source))
        else:
            adjusted_evidence.append(item)
    score = max(0, min(100, sum(item.weight for item in adjusted_evidence)))
    return Correlation(
        left.url,
        right.url,
        score,
        label_for(score),
        adjusted_evidence,
        "Heuristic support from public claims; related name signals are capped, profile certainty is discounted, and ownership is unverified.",
    )


def correlate_findings(findings: list[Finding]) -> list[Correlation]:
    profiles = [finding for finding in findings if finding.status in ACTIVE]
    results: list[Correlation] = []
    for left, right in combinations(profiles, 2):
        if left.provider == right.provider or left.url == right.url:
            continue
        # Matching handles alone cannot reach the report threshold. Skip the
        # many empty catalogue profiles before any text similarity work.
        if not any(
            (
                left.profile.display_name and right.profile.display_name,
                left.profile.bio and right.profile.bio,
                left.profile.links and right.profile.links,
                left.profile.image_url and right.profile.image_url,
                left.profile.image_hash and right.profile.image_hash,
                left.profile.location and right.profile.location,
            )
        ):
            continue
        result = correlate(left, right)
        if result.score >= MIN_REPORTED_SCORE:
            results.append(result)
    return results
