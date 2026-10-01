import pytest

from osintmaster.core.normalization import (
    normalize_text,
    normalize_url,
    normalize_username,
    similarity,
    username_variants,
)


def test_text_username_and_variants():
    assert normalize_text("  Ｓａｍｐｌｅ  USER  ") == "sample user"
    assert normalize_username(" Sample_User ") == "sample_user"
    assert username_variants("sample_user") == [
        "sample_user",
        "sampleuser",
        "sample.user",
        "sample-user",
        "suser",
        "usersample",
    ]
    with pytest.raises(ValueError):
        normalize_username("../private")


def test_url_normalization_removes_tracking_and_fragment():
    assert normalize_url(" HTTPS://EXAMPLE.COM:443/a/?utm_source=x&b=2&fbclid=abc#part ") == (
        "https://example.com/a?b=2"
    )
    with pytest.raises(ValueError):
        normalize_url("file:///tmp/example")


def test_similarity_is_bounded():
    assert similarity("Same BIO", "same bio") == 1
    assert similarity("", "same") == 0
