import pytest
from utils.normalizers import normalize_value

# Tests for normalize_value with threat_type="url"
@pytest.mark.parametrize("value, expected", [
    ("http://example.com", "http://example.com"),
    ("HTTPS://EXAMPLE.COM/PATH/", "https://example.com/path"), # Lowercase, remove trailing slash
    ("example.com/test", "http://example.com/test"), # Add http, remove trailing slash
    ("  HTTPS://Example.com/Another/Path/?query=123  ", "https://example.com/another/path/?query=123"), # Strip, lowercase, remove trailing slash
    ("example.com", "http://example.com"),
    ("example.com/", "http://example.com"),
    ("HTTP://EXAMPLE.COM", "http://example.com"),
    ("ftp://example.com", "ftp://example.com"), # Should not change if not http/https
    ("  example.com/path  ", "http://example.com/path") # Add scheme, strip
])
def test_normalize_url(value, expected):
    assert normalize_value("url", value) == expected

# Tests for normalize_value with threat_type="domain"
@pytest.mark.parametrize("value, expected", [
    ("EXAMPLE.COM", "example.com"), # Lowercase
    ("Example.Co.Uk.", "example.co.uk"), # Lowercase, remove trailing dot
    ("WWW.Example.com", "example.com"), # Remove www.
    ("  www.example.org.  ", "example.org"), # Strip, remove www., remove trailing dot
    ("sub.example.com", "sub.example.com"),
    ("www.sub.example.com", "sub.example.com"),
    ("example.com.", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("  example.com  ", "example.com") # Strip
])
def test_normalize_domain(value, expected):
    assert normalize_value("domain", value) == expected

# Tests for normalize_value with threat_type="ip"
@pytest.mark.parametrize("value, expected", [
    ("  192.168.1.1  ", "192.168.1.1"), # Strip
    ("10.0.0.1", "10.0.0.1"),
    (" 1.2.3.4 ", "1.2.3.4")
])
def test_normalize_ip(value, expected):
    assert normalize_value("ip", value) == expected

# Tests for normalize_value with threat_type="ip_port"
@pytest.mark.parametrize("value, expected", [
    ("  192.168.1.1:8080  ", "192.168.1.1:8080"), # Strip
    ("10.0.0.1:1234", "10.0.0.1:1234"),
    ("  FE80::1:1234 ", "fe80::1:1234") # Lowercase for IPv6 part
])
def test_normalize_ip_port(value, expected):
    assert normalize_value("ip_port", value) == expected

# Tests for normalize_value with threat_type="cidr"
@pytest.mark.parametrize("value, expected", [
    ("  192.168.1.0/24  ", "192.168.1.0/24"), # Strip
    ("10.0.0.0/8", "10.0.0.0/8"),
    ("  FE80::/64 ", "fe80::/64") # Lowercase for IPv6 part
])
def test_normalize_cidr(value, expected):
    assert normalize_value("cidr", value) == expected

# Test with an unknown threat_type (should just strip and return)
@pytest.mark.parametrize("value, expected", [
    ("  TestData  ", "testdata"),
    ("  AnotherValue  ", "anothervalue")
])
def test_normalize_unknown_type(value, expected):
    # For unknown types, the current implementation converts to lowercase and strips.
    # If specific behavior is desired for unknown types, this test should be adjusted.
    assert normalize_value("unknown_type", value) == value.strip().lower()

@pytest.mark.parametrize("threat_type, value, expected", [
    ("url", "  HTTP://Example.com/Path/Trailing/  ", "http://example.com/path/trailing"),
    ("domain", "  WWW.Example.COM.  ", "example.com"),
    ("ip", "  1.2.3.4  ", "1.2.3.4"),
    ("ip_port", "  1.2.3.4:80  ", "1.2.3.4:80"),
    ("cidr", "  10.0.0.0/16  ", "10.0.0.0/16"),
])
def test_normalize_value_general(threat_type, value, expected):
    assert normalize_value(threat_type, value) == expected
