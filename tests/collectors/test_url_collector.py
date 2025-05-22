import pytest
from collectors.url_collector import UrlCollector

@pytest.fixture
def url_collector():
    return UrlCollector()

# Tests for "urlhaus_text"
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("urlhaus_text",
     "# URLhaus Database Dump\n# Last updated: 2023-10-27 10:00:00 UTC\n#\n"
     "http://example.com/malware1\n"
     "https://example.org/phish2\n"
     "# Comment line\n"
     "http://badsite.net/evil.exe\n"
     "  https://anotherbad.com/path  \n" # Leading/trailing spaces
     "ftp://nothttp.com\n" # Should be ignored
     "Just some text\n"
     "",
     [("url", "http://example.com/malware1"),
      ("url", "https://example.org/phish2"),
      ("url", "http://badsite.net/evil.exe"),
      ("url", "https://anotherbad.com/path")]),
    ("urlhaus_text", # Empty data
     "",
     []),
    ("urlhaus_text", # Only comments
     "# Comment 1\n# Comment 2",
     []),
    ("urlhaus_text", # No valid URLs
     "this is not a url\nanother line",
     [])
])
def test_clean_and_extract_urlhaus(url_collector, source_name, raw_data, expected_threats):
    threats = url_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Tests for "openphish"
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("openphish",
     "http://phishing1.com/login\n"
     "https://phishing2.org/access\n"
     "  http://phishing3.net/secure  \n" # Leading/trailing spaces
     "not_a_url\n"
     "ftp://another.com\n" # Should be ignored
     "",
     [("url", "http://phishing1.com/login"),
      ("url", "https://phishing2.org/access"),
      ("url", "http://phishing3.net/secure")]),
    ("openphish", # Empty data
     "",
     []),
    ("openphish", # No valid URLs
     "just text\n12345",
     [])
])
def test_clean_and_extract_openphish(url_collector, source_name, raw_data, expected_threats):
    threats = url_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Tests for "vxvault"
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("vxvault",
     "http://vxsite1.com/payload.php\n"
     "https://vxsite2.org/mal.js\n"
     "# VX Vault comment line\n"
     "  http://vxsite3.net/evil.html  \n" # Leading/trailing spaces
     "some other text\n"
     "ftp://vx.com\n" # Should be ignored
     "",
     [("url", "http://vxsite1.com/payload.php"),
      ("url", "https://vxsite2.org/mal.js"),
      ("url", "http://vxsite3.net/evil.html")]),
    ("vxvault", # Empty data
     "",
     []),
    ("vxvault", # No valid URLs
     "line1\nline2\nline3",
     [])
])
def test_clean_and_extract_vxvault(url_collector, source_name, raw_data, expected_threats):
    threats = url_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Test for an unknown source name
def test_clean_and_extract_unknown_source_url(url_collector):
    raw_data = "http://example.com/test\nhttps://another.com"
    threats = url_collector._clean_and_extract("unknown_url_source", raw_data)
    assert threats == []
