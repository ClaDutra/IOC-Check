"""Consultas a fontes externas de inteligência de ameaças.

Cada fonte devolve um dicionário no mesmo formato (ver provider_result), com
status: ok | not_found | skipped | error. Fontes sem chave, desativadas nas
Configurações ou que não suportam o tipo do indicador ficam como "skipped",
então a aplicação continua funcionando só com a base local.
"""

import base64
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

import requests

from ..ioc_utils import HASH_TYPES, IP_TYPES, is_private_ip
from . import settings
from .report_parsers import analyze_abuseipdb, analyze_urlscan_report

VERDICT_ORDER = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}
VERDICT_LABEL = {"malicious": "malicioso", "suspicious": "suspeito", "clean": "limpo", "unknown": "sem veredito"}


def provider_result(provider, status, verdict="unknown", score=0, summary="", details=None, link=None,
                    flags=None, facts=None, sections=None):
    """Formato comum a todas as fontes.

    flags:    alertas de comportamento, ex. {"text": "Baixa arquivo executável", "level": "bad"}
    facts:    pares rótulo/valor exibidos em "Mais detalhes", ex. {"label": "ASN", "value": "..."}
    sections: listas com título, ex. {"title": "Downloads", "rows": [{"text": ..., "check": hash}]}
    """
    return {
        "provider": provider,
        "status": status,
        "verdict": verdict,
        "score": score,
        "summary": summary,
        "details": details or {},
        "link": link,
        "flags": flags or [],
        "facts": facts or [],
        "sections": sections or [],
    }


def _http_problem(name, response):
    if response.status_code in (401, 403):
        return provider_result(name, "error", summary="Chave de API inválida ou sem permissão")
    if response.status_code == 429:
        return provider_result(name, "error", summary="Limite de requisições da API atingido")
    return provider_result(name, "error", summary=f"Resposta inesperada (HTTP {response.status_code})")


# --- VirusTotal -------------------------------------------------------------

def _virustotal_path(value, ioc_type):
    if ioc_type in IP_TYPES:
        return f"ip_addresses/{value}"
    if ioc_type == "domain":
        return f"domains/{value}"
    if ioc_type in HASH_TYPES:
        return f"files/{value}"
    # URLs são identificadas pelo base64 url-safe sem "=" no final
    url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
    return f"urls/{url_id}"


def query_virustotal(value, ioc_type, key, timeout):
    name = "VirusTotal"
    link = f"https://www.virustotal.com/gui/search/{quote(value, safe='')}"
    response = requests.get(
        f"https://www.virustotal.com/api/v3/{_virustotal_path(value, ioc_type)}",
        headers={"x-apikey": key},
        timeout=timeout,
    )
    if response.status_code == 404:
        return provider_result(name, "not_found", summary="Indicador não encontrado no VirusTotal", link=link)
    if response.status_code != 200:
        return _http_problem(name, response)

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return provider_result(
        name,
        "ok",
        verdict=verdict,
        score=min(100, malicious * 10 + suspicious * 5),
        summary=f"{malicious} de {total} mecanismos classificaram como malicioso",
        details={
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
        },
        link=link,
    )


# --- AbuseIPDB --------------------------------------------------------------

def query_abuseipdb(value, ioc_type, key, timeout):
    name = "AbuseIPDB"
    link = f"https://www.abuseipdb.com/check/{value}"
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        # "verbose" inclui o nome do país e a lista de denúncias com categorias e comentários
        params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
        timeout=timeout,
    )
    if response.status_code != 200:
        return _http_problem(name, response)

    data = response.json().get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))
    reports = data.get("totalReports", 0)

    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    analysis = analyze_abuseipdb(data)
    summary = f"Confiança de abuso {score}% com {reports} denúncia(s) em 90 dias"
    if data.get("isTor"):
        summary += "; nó de saída Tor"

    return provider_result(
        name,
        "ok",
        verdict=verdict,
        score=score,
        summary=summary,
        details={
            "reports": reports,
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": bool(data.get("isTor")),
            "categories": analysis["categories"],
        },
        link=link,
        flags=analysis["flags"],
        facts=analysis["facts"],
        sections=analysis["sections"],
    )


# --- ThreatFox (abuse.ch) ---------------------------------------------------

def _threatfox_matches(ioc, value):
    # O ThreatFox guarda IPs como "ip:porta"; a busca é por trecho, então
    # filtramos para não aceitar 1.2.3.40 ao procurar 1.2.3.4
    ioc, value = ioc.lower(), value.lower()
    return ioc == value or ioc.startswith(value + ":")


def query_threatfox(value, ioc_type, key, timeout):
    name = "ThreatFox"
    link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(value, safe='')}"
    if ioc_type in HASH_TYPES:
        body = {"query": "search_hash", "hash": value}
    else:
        body = {"query": "search_ioc", "search_term": value}

    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json=body,
        headers={"Auth-Key": key},
        timeout=timeout,
    )
    if response.status_code != 200:
        return _http_problem(name, response)

    data = response.json()
    status = data.get("query_status")
    if status in ("no_result", "no_results"):
        return provider_result(name, "not_found", summary="Indicador não encontrado no ThreatFox", link=link)
    if status != "ok":
        return provider_result(name, "error", summary=f"Consulta recusada pela API ({status})")

    entries = [e for e in data.get("data") or [] if isinstance(e, dict)]
    if ioc_type not in HASH_TYPES:
        entries = [e for e in entries if _threatfox_matches(str(e.get("ioc", "")), value)]
    if not entries:
        return provider_result(name, "not_found", summary="Indicador não encontrado no ThreatFox", link=link)

    confidence = max(int(e.get("confidence_level") or 0) for e in entries)
    malware = sorted({e["malware_printable"] for e in entries if e.get("malware_printable")})
    threat_types = sorted({e.get("threat_type_desc") or e.get("threat_type") for e in entries} - {None})
    tags = sorted({tag for e in entries for tag in (e.get("tags") or [])})
    first_seen = min((e["first_seen"] for e in entries if e.get("first_seen")), default=None)

    return provider_result(
        name,
        "ok",
        verdict="malicious" if confidence >= 50 else "suspicious",
        score=max(confidence, 50),
        summary=f"{len(entries)} registro(s): {', '.join(malware[:3]) or 'malware não identificado'} "
                f"(confiança {confidence}%)",
        details={"malware": malware, "threat_types": threat_types, "tags": tags, "first_seen": first_seen},
        link=link,
    )


# --- Hybrid Analysis (sandbox) ----------------------------------------------

HYBRID_URL = "https://www.hybrid-analysis.com/api/v2"
HYBRID_VERDICTS = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "no specific threat": "clean",
    "whitelisted": "clean",
}
HYBRID_TERM_FIELD = {"ipv4": "host", "ipv6": "host", "domain": "domain", "url": "url"}


def query_hybrid_analysis(value, ioc_type, key, timeout):
    name = "Hybrid Analysis"
    link = f"https://www.hybrid-analysis.com/search?query={quote(value, safe='')}"
    headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}

    if ioc_type in HASH_TYPES:
        response = requests.get(f"{HYBRID_URL}/search/hash", headers=headers, params={"hash": value}, timeout=timeout)
        if response.status_code == 405:  # versões antigas da API usam POST
            response = requests.post(f"{HYBRID_URL}/search/hash", headers=headers, data={"hash": value}, timeout=timeout)
    else:
        response = requests.post(
            f"{HYBRID_URL}/search/terms",
            headers=headers,
            data={HYBRID_TERM_FIELD[ioc_type]: value},
            timeout=timeout,
        )

    if response.status_code == 404:
        return provider_result(name, "not_found", summary="Nenhuma análise encontrada na sandbox", link=link)
    if response.status_code != 200:
        return _http_problem(name, response)

    data = response.json()
    reports = data if isinstance(data, list) else (data.get("reports") or data.get("result") or [])
    reports = [r for r in reports if isinstance(r, dict)]
    if not reports:
        return provider_result(name, "not_found", summary="Nenhuma análise encontrada na sandbox", link=link)

    verdicts = [HYBRID_VERDICTS.get(str(r.get("verdict") or "").lower(), "unknown") for r in reports]
    verdict = max(verdicts, key=VERDICT_ORDER.get)
    scores = [r["threat_score"] for r in reports if isinstance(r.get("threat_score"), (int, float))]
    score = int(max(scores)) if scores else {"malicious": 80, "suspicious": 50}.get(verdict, 0)
    families = sorted({r["vx_family"] for r in reports if r.get("vx_family")})

    summary = f"{len(reports)} análise(s) na sandbox; veredito mais grave: {VERDICT_LABEL[verdict]}"
    if families:
        summary += f"; família: {', '.join(families[:3])}"

    return provider_result(
        name, "ok", verdict=verdict, score=score, summary=summary,
        details={"reports": len(reports), "families": families}, link=link,
    )


# --- URLScan.io -------------------------------------------------------------

def _urlscan_query(value, ioc_type):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    if ioc_type in IP_TYPES:
        return f'page.ip:"{escaped}"'
    if ioc_type == "domain":
        return f'page.domain:"{escaped}"'
    if ioc_type == "url":
        return f'page.url:"{escaped}"'
    return f"hash:{value}"


def _urlscan_is_malicious(result):
    verdicts = result.get("verdicts") or {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else verdicts
    return bool(overall.get("malicious"))


def query_urlscan(value, ioc_type, key, timeout):
    name = "URLScan.io"
    query = _urlscan_query(value, ioc_type)
    link = f"https://urlscan.io/search/#{quote(query, safe='')}"
    response = requests.get(
        "https://urlscan.io/api/v1/search/",
        params={"q": query, "size": 100},
        headers={"API-Key": key} if key else {},
        timeout=timeout,
    )
    if response.status_code != 200:
        return _http_problem(name, response)

    data = response.json()
    results = [r for r in data.get("results") or [] if isinstance(r, dict)]
    total = data.get("total", len(results))
    if not results:
        return provider_result(name, "not_found", summary="Nenhuma varredura encontrada no URLScan.io", link=link)

    malicious = sum(1 for r in results if _urlscan_is_malicious(r))
    if malicious >= 2:
        verdict = "malicious"
    elif malicious == 1:
        verdict = "suspicious"
    else:
        verdict = "clean"
    score = min(100, 40 + malicious * 20) if malicious else 0
    summary = f"{total} varredura(s); {malicious} maliciosa(s) entre as {len(results)} mais recentes"

    # Relatório completo da varredura mais recente: downloads, redirecionamentos etc.
    latest = results[0]
    report = _urlscan_report(latest, key, timeout)
    flags, facts, sections = [], [], []
    if report is not None:
        analysis = analyze_urlscan_report(report)
        flags, facts, sections = analysis["flags"], analysis["facts"], analysis["sections"]
        if VERDICT_ORDER[analysis["verdict"]] > VERDICT_ORDER[verdict]:
            verdict = analysis["verdict"]
        score = max(score, analysis["score"])
        behaviour = []
        if analysis["executables"]:
            behaviour.append(f"baixa {analysis['executables']} executável(is)")
        elif analysis["downloads"]:
            behaviour.append(f"baixa {analysis['downloads']} arquivo(s)")
        if analysis["redirects"]:
            behaviour.append(f"{analysis['redirects']} redirecionamento(s)")
        if behaviour:
            summary += f". Última varredura: {', '.join(behaviour)}"
    else:
        flags.append({"text": "Relatório detalhado da última varredura indisponível", "level": "info"})

    return provider_result(
        name,
        "ok",
        verdict=verdict,
        score=score,
        summary=summary,
        details={
            "total": total,
            "malicious": malicious,
            "last_scan": (latest.get("task") or {}).get("time"),
        },
        link=latest.get("result") or link,
        flags=flags,
        facts=facts,
        sections=sections,
    )


def _urlscan_report(search_result, key, timeout):
    """Busca o relatório completo de uma varredura. Falhas aqui não invalidam a busca."""
    uuid = search_result.get("_id") or (search_result.get("task") or {}).get("uuid")
    if not uuid:
        return None
    try:
        response = requests.get(
            f"https://urlscan.io/api/v1/result/{quote(str(uuid), safe='')}/",
            headers={"API-Key": key} if key else {},
            timeout=timeout,
        )
        if response.status_code != 200:
            return None
        report = response.json()
    except (requests.RequestException, ValueError):
        return None
    return report if isinstance(report, dict) else None


# --- Registro das fontes ----------------------------------------------------

@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    query: Callable
    types: frozenset
    key_required: bool
    signup_url: str
    description: str


ALL_TYPES = frozenset(IP_TYPES | HASH_TYPES | {"domain", "url"})

PROVIDERS = [
    Provider("virustotal", "VirusTotal", query_virustotal, ALL_TYPES, True,
             "https://www.virustotal.com/gui/join-us",
             "Reputação em dezenas de antivírus e mecanismos de análise."),
    Provider("abuseipdb", "AbuseIPDB", query_abuseipdb, frozenset(IP_TYPES), True,
             "https://www.abuseipdb.com/register",
             "Denúncias da comunidade sobre IPs usados em ataques."),
    Provider("threatfox", "ThreatFox", query_threatfox, ALL_TYPES, True,
             "https://auth.abuse.ch/",
             "Base do abuse.ch com IOCs de malware, botnets e C2."),
    Provider("hybrid_analysis", "Hybrid Analysis", query_hybrid_analysis, ALL_TYPES, True,
             "https://www.hybrid-analysis.com/signup",
             "Relatórios de sandbox (execução de arquivos e URLs)."),
    Provider("urlscan", "URLScan.io", query_urlscan, frozenset(IP_TYPES | {"domain", "url", "sha256"}), False,
             "https://urlscan.io/user/signup",
             "Varreduras públicas de sites; funciona sem chave, com limite menor."),
]
PROVIDERS_BY_ID = {p.id: p for p in PROVIDERS}

# Indicadores usados no botão "Testar conexão" das Configurações
TEST_SAMPLES = {
    "virustotal": ("8.8.8.8", "ipv4"),
    "abuseipdb": ("8.8.8.8", "ipv4"),
    "threatfox": ("example.com", "domain"),
    "hybrid_analysis": ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256"),
    "urlscan": ("example.com", "domain"),
}


def provider_state(provider):
    """Se a fonte está ativa e, se não estiver, o motivo."""
    enabled = settings.get(f"{provider.id}_enabled")
    has_key = bool(settings.get(f"{provider.id}_api_key"))
    if not enabled:
        reason = "Desativada nas configurações"
    elif provider.key_required and not has_key:
        reason = "Chave de API não configurada"
    else:
        reason = None
    return {"enabled": enabled, "has_key": has_key, "active": reason is None, "reason": reason}


def run_provider(provider, value, ioc_type, ignore_disabled=False):
    name = provider.name
    state = provider_state(provider)
    if not state["enabled"] and not ignore_disabled:
        return provider_result(name, "skipped", summary="Fonte desativada nas configurações")
    if ioc_type not in provider.types:
        return provider_result(name, "skipped", summary="Tipo de indicador não suportado por esta fonte")
    if is_private_ip(value, ioc_type):
        return provider_result(name, "skipped", summary="IP privado/reservado não é consultado")
    if provider.key_required and not state["has_key"]:
        return provider_result(name, "skipped", summary="Chave de API não configurada")

    key = settings.get(f"{provider.id}_api_key")
    timeout = settings.get("provider_timeout")
    try:
        return provider.query(value, ioc_type, key, timeout)
    except requests.exceptions.JSONDecodeError:
        return provider_result(name, "error", summary="Resposta da API em formato inesperado")
    except requests.RequestException as exc:
        return provider_result(name, "error", summary=f"Falha de conexão: {exc.__class__.__name__}")
    except (KeyError, TypeError, ValueError, AttributeError):
        return provider_result(name, "error", summary="Resposta da API em formato inesperado")


def run_all(value, ioc_type):
    return [run_provider(p, value, ioc_type) for p in PROVIDERS]


def configured_providers():
    return [{"id": p.id, "name": p.name, **provider_state(p)} for p in PROVIDERS]
