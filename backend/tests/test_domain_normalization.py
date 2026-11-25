"""
backend/tests/test_domain_normalization.py
Unit tests for domain parsing, cleaning, punycode encoding, and syntax validation.
"""

import pytest

from app.utils.domain import normalize_domain


def test_standard_domain_normalization():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("  sub.example.com  ") == "sub.example.com"


def test_scheme_and_path_stripping():
    assert normalize_domain("https://thepiratebay.org/browse/100") == "thepiratebay.org"
    assert normalize_domain("http://wikipedia.org/wiki/India") == "wikipedia.org"
    assert normalize_domain("ftp://files.example.org/download") == "files.example.org"


def test_credentials_port_and_query_stripping():
    assert (
        normalize_domain("https://user:password@portal.example.com:8443/api?query=1#frag")
        == "portal.example.com"
    )
    assert normalize_domain("example.com:8080") == "example.com"
    assert normalize_domain("example.com.") == "example.com"


def test_punycode_idna_conversion():
    # German umlaut
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"
    # Hindi internationalized domain name
    assert normalize_domain("भारत.संगठन") == "xn--h2brj9c.xn--i1b6b1a6a2e"


def test_invalid_domains_raise_value_error():
    invalid_inputs = [
        "",
        "   ",
        "nodots",
        "invalid_label!.com",
        "example..com",
        "foo..bar.com",
        ".",
        "http://",
        "example.123",  # purely numeric TLD
        "a" * 64 + ".com",  # single label > 63 chars
    ]

    for item in invalid_inputs:
        with pytest.raises(ValueError):
            normalize_domain(item)
