import pytest

from app.ioc_utils import is_private_ip, normalize, parse_input, related_host


@pytest.mark.parametrize(
    "raw, expected_type",
    [
        ("8.8.8.8", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("Example.COM", "domain"),
        ("https://site.example/path?a=1", "url"),
        ("user@site.example", "email"),
        ("44D88612FEA8A8F36DE82E1278ABB02F", "md5"),
        ("3395856ce81f2b7382dee72602f798b642f14140", "sha1"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256"),
        ("isto nao e ioc", None),
        ("999.1.1.1", None),
    ],
)
def test_detect_type(raw, expected_type):
    assert normalize(raw)[1] == expected_type


def test_refang_and_normalize():
    assert normalize("hxxp://Phishing[.]Example/Conta") == ("http://phishing.example/Conta", "url")
    assert normalize("evil[.]example") == ("evil.example", "domain")
    assert normalize("  ABCDEF0123456789ABCDEF0123456789 ")[0] == "abcdef0123456789abcdef0123456789"


def test_related_host():
    assert related_host("http://a.example/x", "url") == "a.example"
    assert related_host("x@b.example", "email") == "b.example"
    assert related_host("8.8.8.8", "ipv4") is None


def test_private_ip():
    assert is_private_ip("192.168.0.1", "ipv4")
    assert not is_private_ip("8.8.8.8", "ipv4")


def test_parse_input_removes_duplicates():
    assert parse_input("a.example\nb.example, a.example;c.example") == ["a.example", "b.example", "c.example"]
    assert parse_input(["x", " x ", "y"]) == ["x", "y"]
