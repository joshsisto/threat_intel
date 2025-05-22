import pytest
from collectors.threatfox_collector import ThreatfoxCollector

@pytest.fixture
def threatfox_collector():
    return ThreatfoxCollector()

# Tests for "threatfox_urls"
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("threatfox_urls",
     '"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_printable","malware_alias","malware_malpedia","confidence_level","anonymous","reporter","tags"\n'
     '"2023-10-27 09:50:00","123","http://example.com/malware.exe","url","botnet_cc","win.url","some_malware","alias1","malpedia_link",75,"0","reporter_x","tag1"\n'
     '"2023-10-27 09:40:00","124","https://phishing.site/login.html","url","phishing","win.phish","phisher","alias2",,50,"1","reporter_y",\n'
     '# Comment line in data, should be skipped or handled by parser if it assumes clean CSV\n'
     '"2023-10-26 08:30:00","125","http://baddomain.com/path with spaces","url","malware","win.generic",,,0,"0","reporter_z","tag2,tag3"\n'
     '"2023-10-25 07:20:00","126","ftp://ignored.com/file","url","other",,,,,0,"0","reporter_a",\n'
     '"","","","","","","","","","",,,\n', # Empty line based on field count
     [("url", "http://example.com/malware.exe"),
      ("url", "https://phishing.site/login.html"),
      ("url", "http://baddomain.com/path with spaces")]), # URL with spaces might be an issue for validator, but ThreatFox might provide them
    ("threatfox_urls", # Empty data
     "",
     []),
    ("threatfox_urls", # Header only
     '"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_printable","malware_alias","malware_malpedia","confidence_level","anonymous","reporter","tags"\n',
     []),
    ("threatfox_urls", # Malformed CSV line (too few fields)
     '"2023-10-27 09:50:00","123","http://example.com/malware.exe"\n',
     []), # Expecting skipping of malformed lines
    ("threatfox_urls", # No http/https prefix
     '"2023-10-27 09:50:00","123","example.com/malware.exe","url","botnet_cc",,,,,0,"0","",\n',
     [])
])
def test_clean_and_extract_threatfox_urls(threatfox_collector, source_name, raw_data, expected_threats):
    threats = threatfox_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Tests for "threatfox_domains"
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("threatfox_domains",
     '"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_printable","malware_alias","malware_malpedia","confidence_level","anonymous","reporter","tags"\n'
     '"2023-10-27 09:50:00","223","evil-domain.com","domain","c2","win.mal","evil","alias_d",,75,"0","rep_d","tag_dom"\n'
     '"2023-10-27 09:40:00","224","another.bad.domain.org","domain","malware_site",,,,,50,"1","rep_e",\n'
     '"2023-10-26 08:30:00","225","1.2.3.4","domain","other",,,,,0,"0","rep_f",\n' # IP as domain, should be filtered by validator
     '"2023-10-25 07:20:00","226","not-a-valid-domain-.com","domain","other",,,,,0,"0","rep_g",\n', # Invalid domain
     [("domain", "evil-domain.com"),
      ("domain", "another.bad.domain.org")]),
    ("threatfox_domains", # Empty data
     "",
     []),
    ("threatfox_domains", # Header only
     '"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_printable","malware_alias","malware_malpedia","confidence_level","anonymous","reporter","tags"\n',
     [])
])
def test_clean_and_extract_threatfox_domains(threatfox_collector, source_name, raw_data, expected_threats):
    threats = threatfox_collector._clean_and_extract(source_name, raw_data)
    assert sorted(threats) == sorted(expected_threats)

# Tests for "threatfox_ip_port"
@pytest.mark.parametrize("source_name, raw_data, expected_threats", [
    ("threatfox_ip_port",
     '"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_printable","malware_alias","malware_malpedia","confidence_level","anonymous","reporter","tags"\n'
     '"2023-10-27 09:50:00","323","1.2.3.4:8080","ip:port","c2","win.cnc","cnc_mal","alias_ip",,100,"0","rep_ip","tag_ip"\n'
     '"2023-10-27 09:40:00","324","5.6.7.8:443","ip:port","botnet_cc",,,,,25,"1","rep_ip2",\n'
     '"2023-10-26 08:30:00","325","badip:1234","ip:port","other",,,,,0,"0","rep_ip3",\n' # Invalid IP part
     '"2023-10-25 07:20:00","326","9.10.11.12","ip:port","other",,,,,0,"0","rep_ip4",\n', # Missing port
     [("ip_port", "1.2.3.4:8080"), ("ip", "1.2.3.4"),
      ("ip_port", "5.6.7.8:443"), ("ip", "5.6.7.8")]),
    ("threatfox_ip_port", # Empty data
     "",
     []),
    ("threatfox_ip_port", # Header only
     '"first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_printable","malware_alias","malware_malpedia","confidence_level","anonymous","reporter","tags"\n',
     []),
    ("threatfox_ip_port", # IP without port, should be skipped for ip_port, but might be caught if logic changes
     '"2023-10-27 09:50:00","333","11.22.33.44","ip:port","c2",,,,,100,"0","rep_ip5",\n',
     []),
    ("threatfox_ip_port", # Valid IP, but invalid port part
     '"2023-10-27 09:50:00","334","11.22.33.44:badport","ip:port","c2",,,,,100,"0","rep_ip6",\n',
     [("ip_port", "11.22.33.44:badport"), ("ip", "11.22.33.44")]) # Current parser allows this, validator for ip_port may differ
])
def test_clean_and_extract_threatfox_ip_port(threatfox_collector, source_name, raw_data, expected_threats):
    threats = threatfox_collector._clean_and_extract(source_name, raw_data)
    # Need to sort tuples themselves if the order of (ip, val) vs (ip_port, val) is not guaranteed for the same IP
    assert sorted(threats) == sorted(expected_threats)

# Test for an unknown source name
def test_clean_and_extract_unknown_source_threatfox(threatfox_collector):
    raw_data = '"2023-10-27 09:50:00","999","http://some.url/path","url","generic",,,,,0,"0","",\n'
    threats = threatfox_collector._clean_and_extract("unknown_threatfox_source", raw_data)
    assert threats == []
