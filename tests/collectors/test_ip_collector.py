import pytest
from collectors.ip_collector import IpCollector

@pytest.fixture
def ip_collector():
    return IpCollector()

# Tests for IP sources (feodotracker_ipblocklist, binarydefense, etc.)
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("feodotracker_ipblocklist",
     "1.1.1.1\n# Comment\n2.2.2.2\n\n3.3.3.3 some other text",
     [("ip", "1.1.1.1"), ("ip", "2.2.2.2"), ("ip", "3.3.3.3")]),
    ("binarydefense",
     "4.4.4.4\n5.5.5.5 // Another comment style\n  6.6.6.6",
     [("ip", "4.4.4.4"), ("ip", "5.5.5.5"), ("ip", "6.6.6.6")]),
    ("emergingthreats",
     "7.7.7.7\n8.8.8.BADIP\n9.9.9.9", # Invalid IP in middle
     [("ip", "7.7.7.7"), ("ip", "9.9.9.9")]),
    ("cinsscore",
     "10.0.0.1 ; comment\n10.0.0.2",
     [("ip", "10.0.0.1"), ("ip", "10.0.0.2")]),
    ("elliotech",
     "11.11.11.11\n12.12.12.12",
     [("ip", "11.11.11.11"), ("ip", "12.12.12.12")]),
    ("stamparm",
     "13.13.13.13",
     [("ip", "13.13.13.13")]),
    ("mirai",
     "14.14.14.14\n15.15.15.15",
     [("ip", "14.14.14.14"), ("ip", "15.15.15.15")]),
    ("feodotracker_ipblocklist", # Empty data
     "",
     []),
    ("binarydefense", # Only comments and empty lines
     "# Start\n\n// Another comment\n  ; final comment",
     []),
    ("emergingthreats", # Data with no valid IPs
     "this is not an ip\nanother line",
     []),
    ("cinsscore", # IPs mixed with other text, ensure correct extraction
     "some text 10.20.30.40 here\nand 10.20.30.50 there",
     [("ip", "10.20.30.40"),("ip", "10.20.30.50")])
])
def test_clean_and_extract_ip_sources(ip_collector, source_name, raw_data, expected_threats):
    threats = ip_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Tests for CIDR sources (spamhaus_drop, dshield, firehol)
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("spamhaus_drop",
     "192.168.0.0/24 ; comment\n# Another comment\n10.0.0.0/8\n\n172.16.0.0/12 text after cidr",
     [("cidr", "192.168.0.0/24"), ("cidr", "10.0.0.0/8"), ("cidr", "172.16.0.0/12")]),
    ("dshield",
     "203.0.113.0/24\n// Comment\n2001:db8::/32", # dshield format might include IPv6 CIDRs, validator might not support
     [("cidr", "203.0.113.0/24")]), # Assuming current validator only supports IPv4 CIDR
    ("firehol",
     "198.51.100.0/22\n198.51.100.BAD/22\n198.51.104.0/21", # Invalid CIDR in middle
     [("cidr", "198.51.100.0/22"), ("cidr", "198.51.104.0/21")]),
    ("spamhaus_drop", # Empty data
     "",
     []),
    ("dshield", # Only comments
     "# Main comment\n// Sub comment\n; End comment",
     []),
    ("firehol", # No valid CIDRs
     "this is not a cidr\nanother line without cidr",
     []),
    ("spamhaus_drop", # Mixed content
     "prefix 1.2.3.0/24 suffix\ntext 10.0.0.0/16",
     [("cidr", "1.2.3.0/24"), ("cidr", "10.0.0.0/16")])
])
def test_clean_and_extract_cidr_sources(ip_collector, source_name, raw_data, expected_threats):
    threats = ip_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Test for an unknown source name (should extract nothing or log a warning, current behavior is to return empty list)
def test_clean_and_extract_unknown_source(ip_collector):
    raw_data = "1.1.1.1\n192.168.0.0/24"
    threats = ip_collector._clean_and_extract("unknown_source_name", raw_data)
    assert threats == []

# Test for mixed IP and CIDR in raw_data, but processed by a source_name expecting only one type
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("feodotracker_ipblocklist", # Expects IPs
     "1.1.1.1\n192.168.0.0/24\n2.2.2.2",
     [("ip", "1.1.1.1"), ("ip", "2.2.2.2")]), # Should only get IPs
    ("spamhaus_drop", # Expects CIDRs
     "1.1.1.1\n192.168.0.0/24\n2.2.2.2",
     [("cidr", "192.168.0.0/24")]) # Should only get CIDRs
])
def test_clean_and_extract_mixed_content_specific_source(ip_collector, source_name, raw_data, expected_threats):
    threats = ip_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)
