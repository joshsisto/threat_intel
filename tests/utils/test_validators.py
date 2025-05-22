import pytest
from utils.validators import validate_ip, validate_domain, validate_cidr, validate_url

# Tests for validate_ip
@pytest.mark.parametrize("ip, expected", [
    ("192.168.1.1", True),
    ("0.0.0.0", True),
    ("255.255.255.255", True),
    ("10.0.0.1", True),
    ("172.16.0.1", True),
    ("1.2.3.4", True),
    ("192.168.1.256", False),  # Invalid octet
    ("192.168.1", False),      # Missing octet
    ("192.168.1.1.1", False),  # Too many octets
    ("abc.def.ghi.jkl", False),# Non-numeric
    ("192.168.1.-1", False),   # Negative octet
    ("", False),
    (None, False),
    (12345, False),
    ("256.0.0.0", False),
    ("1.2.3.4.5", False),
    ("1.2.3", False)
])
def test_validate_ip(ip, expected):
    assert validate_ip(ip) == expected

# Tests for validate_domain
@pytest.mark.parametrize("domain, expected", [
    ("example.com", True),
    ("sub.example.com", True),
    ("example.co.uk", True),
    ("www.example.com", True),
    ("example-domain.com", True),
    ("xn--p1ai.com.ru", True), # IDN example (Punycode)
    ("example.123", True), # TLD can be numeric (though rare)
    ("localhost", False), # Typically not a public FQDN for this context
    ("example", False),          # No TLD
    (".com", False),             # Missing domain name
    ("example.com.", True),     # Trailing dot is technically valid
    ("-example.com", False),    # Starts with hyphen
    ("example-.com", False),    # Ends with hyphen before TLD
    ("example..com", False),    # Double dot
    ("192.168.1.1", False),    # IP address is not a domain
    ("", False),
    (None, False),
    ("example.com/", False),    # Contains invalid char
    ("ex ample.com", False),    # Contains space
    ("a"*256 + ".com", False),  # Too long
    ("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com", False) # Over 255 chars
])
def test_validate_domain(domain, expected):
    assert validate_domain(domain) == expected

# Tests for validate_cidr
@pytest.mark.parametrize("cidr, expected", [
    ("192.168.1.0/24", True),
    ("0.0.0.0/0", True),
    ("10.0.0.0/8", True),
    ("172.16.0.0/12", True),
    ("255.255.255.255/32", True),
    ("192.168.1.0/33", False),   # Invalid prefix
    ("192.168.1.0/-1", False),   # Invalid prefix
    ("192.168.1.256/24", False), # Invalid IP part
    ("192.168.1.0", False),      # Missing prefix
    ("192.168.1.0/24/12", False),# Too many slashes
    ("abc.def.ghi.jkl/24", False),# Non-numeric IP
    ("", False),
    (None, False),
    ("1.2.3.4/0", True),
    ("1.2.3.4/32", True),
])
def test_validate_cidr(cidr, expected):
    assert validate_cidr(cidr) == expected

# Tests for validate_url
@pytest.mark.parametrize("url, expected", [
    ("http://example.com", True),
    ("https://example.com", True),
    ("http://www.example.com", True),
    ("https://sub.example.co.uk/path?query=value#fragment", True),
    ("http://example.com:8080", True),
    ("https://192.168.1.1/test", True), # URL with IP
    ("ftp://example.com", False),     # Invalid scheme
    ("http//example.com", False),    # Missing colon
    ("http:/example.com", False),    # Missing slash
    ("example.com", False),          # Missing scheme
    ("http://localhost:8000", True),
    ("http://example.com/", True),
    ("https://example.com/a%20b", True), # URL encoded space
    ("http://example.com?" + "a"*2040, True), # Long query string, still valid
    ("http://example.com/" + "a"*2040, True), # Long path, still valid
    ("http://" + "a"*250 + ".com", True), # Long domain
    ("http://example.com/" + "a"*2049, False), # URL too long (path part makes it exceed limit)
    ("https://example.com/very_long_path_" + "a"*2000 + "_end", False), # Exceeds 2048
    ("", False),
    (None, False),
    ("http://exam_ple.com", False), # Invalid char in domain part
    ("http://example.com/path with spaces", False) # Unencoded space
])
def test_validate_url(url, expected):
    assert validate_url(url) == expected
