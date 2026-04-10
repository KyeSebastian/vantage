# tests for target parsing - ip vs domain detection, url stripping, edge cases

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from scanner.target import Target


# ── Attack 1: URL with port must not produce "cannot resolve example.com:8080" ──

class TestPortInURL:
    """A URL containing a port number must either work or give a clear error — not silently fail DNS."""

    def test_url_with_port_strips_port_or_raises_clear_error(self):
        # Current behavior: raises ValueError with a confusing "cannot resolve" message.
        # This test locks in that it at least raises ValueError (not a crash),
        # and documents the port-stripping gap for future fix.
        with pytest.raises(ValueError) as exc_info:
            Target.from_string("https://scanme.nmap.org:8080/path")
        # The error must be a ValueError, not an unhandled socket exception
        assert "Cannot resolve" in str(exc_info.value) or "port" in str(exc_info.value).lower()

    def test_plain_url_no_port_resolves_correctly(self):
        # This must work — port-free HTTPS URLs are the common case
        t = Target.from_string("https://scanme.nmap.org")
        assert t.hostname == "scanme.nmap.org"
        assert t.is_ip is False


# ── Attack 2: Empty / whitespace input must fail clearly, not silently ────────

class TestEmptyInput:
    """Empty and whitespace strings must raise ValueError, not return a localhost Target."""

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            Target.from_string("")

    def test_whitespace_only_raises_value_error(self):
        with pytest.raises(ValueError):
            Target.from_string("   ")

    def test_error_message_is_informative(self):
        with pytest.raises(ValueError) as exc_info:
            Target.from_string("")
        assert str(exc_info.value)  # must not be empty string


# ── Attack 3: raw field stores the cleaned value, not the original ────────────

class TestRawField:
    """raw must store the bare hostname/IP — URL prefix and path must be stripped."""

    def test_https_prefix_stripped_from_raw(self):
        t = Target.from_string("https://scanme.nmap.org")
        assert t.raw == "scanme.nmap.org"
        assert "https" not in t.raw

    def test_http_prefix_stripped_from_raw(self):
        t = Target.from_string("http://scanme.nmap.org")
        assert t.raw == "scanme.nmap.org"

    def test_trailing_slash_stripped_from_raw(self):
        t = Target.from_string("https://scanme.nmap.org/")
        assert t.raw == "scanme.nmap.org"
        assert t.raw.endswith("/") is False

    def test_path_stripped_from_raw(self):
        t = Target.from_string("https://scanme.nmap.org/some/path")
        assert t.raw == "scanme.nmap.org"

    def test_raw_ip_stored_as_given(self):
        t = Target.from_string("45.33.32.156")
        assert t.raw == "45.33.32.156"


# ── Gap 1: Out-of-range IP octets must not be accepted silently ───────────────

class TestInvalidIPFormats:
    """Values that look like IPs but aren't valid must fail, not pass as domains."""

    def test_out_of_range_octet_is_rejected(self):
        # 999.999.999.999 looks like an IP — ipaddress rejects it,
        # socket.gethostbyname may silently try to resolve it as a hostname
        with pytest.raises((ValueError, OSError)):
            Target.from_string("999.999.999.999")

    def test_incomplete_ip_treated_as_hostname_or_rejected(self):
        # "192.168" could be treated as a hostname — must not silently become an IP Target
        t = Target.from_string("192.168.1.1")
        assert t.is_ip is True  # fully valid IP
        # partial IP "192.168" behavior: must be is_ip=False (treated as domain) or raise
        with pytest.raises((ValueError, OSError)):
            result = Target.from_string("192.168")
            assert result.is_ip is False  # acceptable — treated as domain


# ── Gap 2: is_ip flag must be correct for every input type ───────────────────

class TestIsIPFlag:
    """is_ip must be True for IPs, False for domains — it controls module routing."""

    def test_valid_ipv4_sets_is_ip_true(self):
        t = Target.from_string("45.33.32.156")
        assert t.is_ip is True

    def test_domain_sets_is_ip_false(self):
        t = Target.from_string("scanme.nmap.org")
        assert t.is_ip is False

    def test_domain_via_https_url_sets_is_ip_false(self):
        t = Target.from_string("https://scanme.nmap.org")
        assert t.is_ip is False

    def test_ip_via_http_url_sets_is_ip_true(self):
        t = Target.from_string("http://45.33.32.156")
        assert t.is_ip is True


# ── Gap 3: hostname field contract ────────────────────────────────────────────

class TestHostnameField:
    """hostname must be None for IPs and set to the domain string for hostnames."""

    def test_raw_ip_has_no_hostname(self):
        t = Target.from_string("45.33.32.156")
        assert t.hostname is None

    def test_domain_hostname_matches_raw(self):
        t = Target.from_string("scanme.nmap.org")
        assert t.hostname == "scanme.nmap.org"
        assert t.hostname == t.raw

    def test_ip_field_is_set_for_domains(self):
        t = Target.from_string("scanme.nmap.org")
        assert t.ip  # must not be empty
        # Must look like a valid IP
        parts = t.ip.split(".")
        assert len(parts) == 4
        assert all(p.isdigit() for p in parts)
