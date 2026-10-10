"""Detecção, normalização e "refang" de indicadores de comprometimento (IOCs)."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_TYPES = set(HASH_LENGTHS.values())
IP_TYPES = {"ipv4", "ipv6"}
TYPE_LABELS = {
    "ipv4": "IPv4", "ipv6": "IPv6", "domain": "Domínio", "url": "URL",
    "email": "E-mail", "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256",
}
IOC_TYPES = list(TYPE_LABELS)

HEX_RE = re.compile(r"^[a-f0-9]+$")
URL_RE = re.compile(r"^(https?|ftp)://[^\s/?#]+[^\s]*$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
SPLIT_RE = re.compile(r"[\s,;]+")

# Formas comuns de "desarmar" indicadores em relatórios de ameaças
DEFANG_REPLACEMENTS = [
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("[at]", "@"),
]


def refang(value):
    """Converte 'hxxp://site[.]com' de volta para 'http://site.com'."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = re.sub(r"^fxp", "ftp", v, flags=re.IGNORECASE)
    for old, new in DEFANG_REPLACEMENTS:
        v = v.replace(old, new)
    return v


def detect_type(value):
    """Retorna o tipo do indicador ou None se o formato não for reconhecido."""
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass

    lower = value.lower()
    if HEX_RE.match(lower) and len(lower) in HASH_LENGTHS:
        return HASH_LENGTHS[len(lower)]
    if URL_RE.match(value):
        return "url"
    if EMAIL_RE.match(lower):
        return "email"
    if DOMAIN_RE.match(lower):
        return "domain"
    return None


def normalize(raw):
    """Retorna (valor_normalizado, tipo). O tipo é None para entradas inválidas."""
    value = refang(raw)
    ioc_type = detect_type(value)

    if ioc_type == "url":
        # Esquema e host não diferenciam maiúsculas; caminho e query sim
        parts = urlsplit(value)
        value = urlunsplit(
            (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
        )
    elif ioc_type == "ipv6":
        value = str(ipaddress.ip_address(value))
    elif ioc_type is not None:
        value = value.lower()
    return value, ioc_type


def related_host(value, ioc_type):
    """Domínio associado a uma URL ou e-mail, usado para buscar correspondências na base local."""
    if ioc_type == "url":
        return urlsplit(value).hostname
    if ioc_type == "email":
        return value.split("@", 1)[1]
    return None


def is_private_ip(value, ioc_type):
    if ioc_type not in IP_TYPES:
        return False
    ip = ipaddress.ip_address(value)
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local


def parse_input(data):
    """Aceita texto livre (um por linha, vírgula ou espaço) ou lista; remove duplicados."""
    items = data if isinstance(data, list) else SPLIT_RE.split(str(data or ""))
    seen, result = set(), []
    for item in items:
        item = str(item).strip()
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result
