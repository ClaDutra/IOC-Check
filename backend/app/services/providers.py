"""Consultas a fontes externas de inteligência de ameaças.

Cada fonte devolve um dicionário no mesmo formato (ver provider_result), com
status: ok | not_found | skipped | error. Fontes sem chave, desativadas nas
Configurações ou que não suportam o tipo do indicador ficam como "skipped",
então a aplicação continua funcionando só com a base local.

Todas as chaves são de planos gratuitos: cada chamada HTTP passa por _http(),
que registra o consumo em services/quota.py e respeita os limites de cada fonte.
"""

import base64
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote, urlsplit

import requests

from ..ioc_utils import HASH_TYPES, IP_TYPES, detect_type, is_private_ip, related_host
from . import activity, quota, settings
from .report_parsers import (
    analyze_abuseipdb,
    analyze_hybrid_overview,
    analyze_ipinfo,
    analyze_mxtoolbox,
    analyze_threatfox,
    analyze_urlscan_report,
    analyze_virustotal,
)

VERDICT_ORDER = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}
VERDICT_LABEL = {"malicious": "malicioso", "suspicious": "suspeito", "clean": "limpo", "unknown": "sem veredito"}


def provider_result(provider, status, verdict="unknown", score=0, summary="", details=None, link=None,
                    flags=None, facts=None, sections=None, media=None, transient=False):
    """Formato comum a todas as fontes.

    flags:     alertas de comportamento, ex. {"text": "Baixa arquivo executável", "level": "bad"}
    facts:     pares rótulo/valor exibidos em "Mais detalhes", ex. {"label": "ASN", "value": "..."}
    sections:  listas com título, ex. {"title": "Downloads", "rows": [{"text": ..., "check": hash}]}
    media:     imagens, ex. a captura de tela do URLScan.io {"type": "image", "url": ..., "caption": ...}
    transient: True quando a fonte não respondeu por um motivo passageiro (ex.: limite por minuto);
               o cache então guarda o resultado por pouco tempo, para tentar de novo em breve.
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
        "media": media or [],
        "transient": transient,
    }


def _http(provider_id, method, url, **kwargs):
    """Faz a chamada HTTP, registra o consumo da cota gratuita e grava a chamada nos Logs
    (endereço, parâmetros, código e começo da resposta; nunca os cabeçalhos com a chave)."""
    started = time.perf_counter()
    try:
        response = getattr(requests, method)(url, **kwargs)
    except requests.RequestException as exc:
        activity.api_call(provider_id, method, url, kwargs, started, error=exc)
        raise
    quota.record(provider_id, response)
    activity.api_call(provider_id, method, url, kwargs, started, response=response)
    return response


def _http_problem(name, response, provider_id=None):
    if response.status_code in (401, 403):
        return provider_result(name, "error", summary="Chave de API inválida ou sem permissão")
    if response.status_code == 429:
        reason = (quota.check(provider_id) if provider_id else None) or "Limite gratuito da API atingido"
        return provider_result(name, "skipped", summary=reason, transient=True)
    return provider_result(name, "error", summary=f"Resposta inesperada (HTTP {response.status_code})")


def _raise_verdict(verdict, score, analysis):
    """Os sinais encontrados nos relatórios podem elevar o veredito, nunca rebaixar."""
    if analysis.get("verdict") and VERDICT_ORDER[analysis["verdict"]] > VERDICT_ORDER[verdict]:
        verdict = analysis["verdict"]
    return verdict, max(score, analysis.get("score") or 0)


# --- VirusTotal -------------------------------------------------------------
# API pública: 4 consultas/min, 500/dia, uso não comercial. Uma chamada por indicador.

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
    response = _http(
        "virustotal", "get",
        f"https://www.virustotal.com/api/v3/{_virustotal_path(value, ioc_type)}",
        headers={"x-apikey": key},
        timeout=timeout,
    )
    if response.status_code == 404:
        return provider_result(name, "not_found", summary="Indicador não encontrado no VirusTotal", link=link)
    if response.status_code != 200:
        return _http_problem(name, response, "virustotal")

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int))

    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"
    score = min(100, malicious * 10 + suspicious * 5)

    analysis = analyze_virustotal(attributes, ioc_type)
    verdict, score = _raise_verdict(verdict, score, analysis)

    return provider_result(
        name,
        "ok",
        verdict=verdict,
        score=score,
        summary=f"{malicious} de {total} mecanismos classificaram como malicioso"
                + (f" e {suspicious} como suspeito" if suspicious else ""),
        details={
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
        },
        link=link,
        flags=analysis["flags"],
        facts=analysis["facts"],
        sections=analysis["sections"],
    )


# --- AbuseIPDB --------------------------------------------------------------
# Conta gratuita: 1.000 consultas/dia (informado nos cabeçalhos X-RateLimit-*).

def query_abuseipdb(value, ioc_type, key, timeout):
    name = "AbuseIPDB"
    link = f"https://www.abuseipdb.com/check/{value}"
    response = _http(
        "abuseipdb", "get",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        # "verbose" inclui o nome do país e a lista de denúncias com categorias e comentários
        params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
        timeout=timeout,
    )
    if response.status_code != 200:
        return _http_problem(name, response, "abuseipdb")

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
# Gratuito sob "fair use"; a conta informa 100.000 consultas/dia nos cabeçalhos.

def _ioc_host(ioc):
    """Host de um IOC do ThreatFox, que pode ser URL, "ip:porta" ou domínio."""
    ioc = str(ioc or "").lower()
    if "://" in ioc:
        return urlsplit(ioc).hostname or ""
    return ioc.rsplit(":", 1)[0] if ioc.count(":") == 1 else ioc


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

    response = _http("threatfox", "post", "https://threatfox-api.abuse.ch/api/v1/",
                     json=body, headers={"Auth-Key": key}, timeout=timeout)
    if response.status_code != 200:
        return _http_problem(name, response, "threatfox")

    data = response.json()
    status = data.get("query_status")
    if status in ("no_result", "no_results"):
        return provider_result(name, "not_found", summary="Indicador não encontrado no ThreatFox", link=link)
    if status != "ok":
        return provider_result(name, "error", summary=f"Consulta recusada pela API ({status})")

    found = [e for e in data.get("data") or [] if isinstance(e, dict)]
    entries, related = found, []
    if ioc_type not in HASH_TYPES:
        entries = [e for e in found if _threatfox_matches(str(e.get("ioc", "")), value)]
        # Para IPs e domínios, URLs de malware hospedadas no mesmo host também importam
        if ioc_type in IP_TYPES or ioc_type == "domain":
            related = [e for e in found if e not in entries and _ioc_host(e.get("ioc")) == value.lower()]
    if not entries and not related:
        return provider_result(name, "not_found", summary="Indicador não encontrado no ThreatFox", link=link)

    analysis = analyze_threatfox(entries, related)
    if entries:
        confidence = max(int(e.get("confidence_level") or 0) for e in entries)
        malware = sorted({e["malware_printable"] for e in entries if e.get("malware_printable")})
        verdict, score = ("malicious" if confidence >= 50 else "suspicious"), max(confidence, 50)
        summary = f"{len(entries)} registro(s): {', '.join(malware[:3]) or 'malware não identificado'} (confiança {confidence}%)"
    else:
        malware = sorted({e["malware_printable"] for e in related if e.get("malware_printable")})
        summary = f"Não listado diretamente, mas hospeda {len(related)} IOC(s) de malware ({', '.join(malware[:3]) or '?'})"
        if ioc_type in IP_TYPES:
            verdict, score = "suspicious", 60
        else:
            # Domínios populares (github.com, drive.google.com...) hospedam arquivos de terceiros:
            # é um aviso, não prova de que o domínio em si seja malicioso
            verdict, score = "unknown", 0
            summary += "; domínios de hospedagem pública também aparecem aqui"

    return provider_result(
        name, "ok", verdict=verdict, score=score, summary=summary,
        details={"malware": malware, "related": len(related)},
        link=link, flags=analysis["flags"], facts=analysis["facts"], sections=analysis["sections"],
    )


# --- Hybrid Analysis (sandbox) ----------------------------------------------
# Chaves gratuitas ("restricted") só acessam buscas: /search/hash e /overview.
# A antiga busca por termos (IP, domínio, URL) não está disponível para elas,
# por isso a fonte consulta apenas hashes. Limite: 200/min e 2.000/hora.

HYBRID_URL = "https://www.hybrid-analysis.com/api/v2"


def query_hybrid_analysis(value, ioc_type, key, timeout):
    name = "Hybrid Analysis"
    headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}

    # 1) Busca pelo hash: descobre o SHA256 e o estado das análises na sandbox
    response = _http("hybrid_analysis", "get", f"{HYBRID_URL}/search/hash",
                     headers=headers, params={"hash": value}, timeout=timeout)
    if response.status_code == 404:
        return provider_result(name, "not_found", summary="Arquivo nunca analisado pela sandbox")
    if response.status_code != 200:
        return _http_problem(name, response, "hybrid_analysis")
    data = response.json()
    sha256s = [s for s in data.get("sha256s") or [] if isinstance(s, str)]
    reports = [r for r in data.get("reports") or [] if isinstance(r, dict)]
    if not sha256s:
        return provider_result(name, "not_found", summary="Arquivo nunca analisado pela sandbox")
    sha256 = sha256s[0]
    link = f"https://www.hybrid-analysis.com/sample/{sha256}"

    # 2) Visão geral do arquivo: veredito, família, detecção dos antivírus etc.
    response = _http("hybrid_analysis", "get", f"{HYBRID_URL}/overview/{sha256}", headers=headers, timeout=timeout)
    if response.status_code == 404:
        return provider_result(name, "not_found", summary="Arquivo sem visão geral na sandbox", link=link)
    if response.status_code != 200:
        return _http_problem(name, response, "hybrid_analysis")

    analysis = analyze_hybrid_overview(response.json(), reports)
    verdict = analysis["verdict"]
    summary = f"Veredito da sandbox: {VERDICT_LABEL[verdict]}"
    family = next((f["text"].split(": ", 1)[1] for f in analysis["flags"] if f["text"].startswith("Família:")), None)
    if family:
        summary += f"; família {family}"
    return provider_result(
        name, "ok", verdict=verdict, score=analysis["score"], summary=summary,
        details={"sha256": sha256, "reports": len(reports)}, link=link,
        flags=analysis["flags"], facts=analysis["facts"], sections=analysis["sections"],
    )


# --- URLScan.io -------------------------------------------------------------
# Com chave gratuita: 120 buscas/min (informado nos cabeçalhos X-Rate-Limit-*).

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


def _urlscan_screenshot(search_result, report):
    """Captura de tela da página na varredura mais recente (imagem pública do URLScan.io)."""
    task = (report or {}).get("task") or search_result.get("task") or {}
    url = search_result.get("screenshot") or task.get("screenshotURL")
    if not url or not str(url).startswith("https://urlscan.io/screenshots/"):
        return []
    when = str(task.get("time") or "")[:10]
    return [{
        "type": "image",
        "url": url,
        "caption": f"Captura de tela da página feita pelo URLScan.io" + (f" em {when}" if when else ""),
        "link": task.get("reportURL") or _urlscan_report_page(search_result),
    }]


def query_urlscan(value, ioc_type, key, timeout):
    name = "URLScan.io"
    query = _urlscan_query(value, ioc_type)
    link = f"https://urlscan.io/search/#{quote(query, safe='')}"
    response = _http("urlscan", "get", "https://urlscan.io/api/v1/search/",
                     params={"q": query, "size": 100},
                     headers={"API-Key": key} if key else {}, timeout=timeout)
    if response.status_code != 200:
        return _http_problem(name, response, "urlscan")

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
        verdict, score = _raise_verdict(verdict, score, analysis)
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
        link=_urlscan_report_page(latest) or link,
        flags=flags,
        facts=facts,
        sections=sections,
        media=_urlscan_screenshot(latest, report),
    )


def _urlscan_report_page(search_result):
    """Página do relatório para pessoas (o campo "result" da busca aponta para a API)."""
    uuid = search_result.get("_id") or (search_result.get("task") or {}).get("uuid")
    return f"https://urlscan.io/result/{quote(str(uuid), safe='')}/" if uuid else None


def _urlscan_report(search_result, key, timeout):
    """Busca o relatório completo de uma varredura. Falhas aqui não invalidam a busca."""
    uuid = search_result.get("_id") or (search_result.get("task") or {}).get("uuid")
    if not uuid or quota.check("urlscan"):
        return None
    try:
        response = _http("urlscan", "get", f"https://urlscan.io/api/v1/result/{quote(str(uuid), safe='')}/",
                         headers={"API-Key": key} if key else {}, timeout=timeout)
        if response.status_code != 200:
            return None
        report = response.json()
    except (requests.RequestException, ValueError):
        return None
    return report if isinstance(report, dict) else None


# --- MxToolbox --------------------------------------------------------------
# Conta gratuita: 64 consultas DNS por dia e nenhuma de "rede" (blacklist, http,
# smtp...), zerando à meia-noite UTC. Por isso só usamos comandos DNS: MX, SPF e
# DMARC para domínios (3 consultas) e PTR para IPs (1 consulta).

MXTOOLBOX_URL = "https://api.mxtoolbox.com/api/v1/Lookup"


def _mxtoolbox_target(value, ioc_type):
    """(alvo, comandos): domínio de URL/e-mail ou o próprio IP."""
    host = related_host(value, ioc_type) or value
    if ioc_type in IP_TYPES or detect_type(host) in IP_TYPES:
        return host, ["ptr"]
    return host, ["mx", "spf", "dmarc"]


def query_mxtoolbox(value, ioc_type, key, timeout):
    name = "MxToolbox"
    target, commands = _mxtoolbox_target(value, ioc_type)
    link = f"https://mxtoolbox.com/SuperTool.aspx?action={commands[0]}%3a{quote(target, safe='')}&run=toolpage"
    lookups, notes = {}, []
    for command in commands:
        paused = quota.check("mxtoolbox")
        if paused:  # não gasta mais consultas do que o plano gratuito permite
            if not lookups:
                return provider_result(name, "skipped", summary=paused, transient=True)
            notes.append(f"{command.upper()} não consultado: {paused}")
            break
        response = _http("mxtoolbox", "get", f"{MXTOOLBOX_URL}/{command}/",
                         headers={"Authorization": key, "Accept": "application/json"},
                         params={"argument": target}, timeout=timeout)
        if response.status_code != 200:
            if lookups and response.status_code == 429:
                notes.append(f"{command.upper()} não consultado: limite gratuito atingido")
                break
            return _http_problem(name, response, "mxtoolbox")
        data = response.json()
        if isinstance(data, dict):  # entrada inválida para o comando volta como texto
            lookups[command] = data

    if not lookups:
        return provider_result(name, "not_found", summary="A MxToolbox não retornou registros para este alvo",
                               link=link)
    analysis = analyze_mxtoolbox(lookups)
    summary = f"{target}: {analysis['summary']}" + (f" ({'; '.join(notes)})" if notes else "")
    # Saúde de DNS e de e-mail é contexto, não reputação: não altera o veredito
    return provider_result(
        name, "ok", summary=summary, link=link,
        details={"target": target, "commands": list(lookups)},
        flags=analysis["flags"], facts=analysis["facts"], sections=analysis["sections"],
        transient=bool(notes),
    )


# --- IPinfo -----------------------------------------------------------------
# IPinfo Lite (plano gratuito): ASN, organização, domínio do AS, país e continente.

def query_ipinfo(value, ioc_type, key, timeout):
    name = "IPinfo"
    link = f"https://ipinfo.io/{value}"
    response = _http("ipinfo", "get", f"https://api.ipinfo.io/lite/{quote(value, safe=':')}",
                     headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
                     timeout=timeout)
    if response.status_code == 404:
        return provider_result(name, "not_found", summary="IP sem informações no IPinfo", link=link)
    if response.status_code != 200:
        return _http_problem(name, response, "ipinfo")
    data = response.json()
    if data.get("bogon"):
        return provider_result(name, "not_found", summary="Endereço reservado (bogon), sem dono público", link=link)
    analysis = analyze_ipinfo(data)
    return provider_result(
        name, "ok", summary=analysis["summary"], link=link,
        details={"asn": data.get("asn"), "as_name": data.get("as_name"), "country": data.get("country_code")},
        facts=analysis["facts"],
    )


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
    terms: str


ALL_TYPES = frozenset(IP_TYPES | HASH_TYPES | {"domain", "url"})

PROVIDERS = [
    Provider("virustotal", "VirusTotal", query_virustotal, ALL_TYPES, True,
             "https://www.virustotal.com/gui/join-us",
             "Reputação em dezenas de antivírus, categorias, sandboxes e regras YARA.",
             "API pública: 4 consultas/min e 500/dia, apenas uso pessoal e não comercial."),
    Provider("abuseipdb", "AbuseIPDB", query_abuseipdb, frozenset(IP_TYPES), True,
             "https://www.abuseipdb.com/register",
             "Denúncias da comunidade sobre IPs usados em ataques.",
             "Conta gratuita: 1.000 consultas/dia."),
    Provider("threatfox", "ThreatFox", query_threatfox, ALL_TYPES, True,
             "https://auth.abuse.ch/",
             "Base do abuse.ch com IOCs de malware, botnets e C2.",
             "Gratuito sob política de uso justo (fair use), sem fins comerciais."),
    Provider("hybrid_analysis", "Hybrid Analysis", query_hybrid_analysis, frozenset(HASH_TYPES), True,
             "https://www.hybrid-analysis.com/signup",
             "Relatórios de sandbox e antivírus para arquivos (hash).",
             "Chave gratuita (restricted): só buscas, 200/min e 2.000/hora."),
    Provider("urlscan", "URLScan.io", query_urlscan, frozenset(IP_TYPES | {"domain", "url", "sha256"}), False,
             "https://urlscan.io/user/signup",
             "Varreduras públicas de sites, com captura de tela; funciona sem chave.",
             "Conta gratuita: 120 buscas/min; não é permitido copiar a base em massa."),
    Provider("mxtoolbox", "MxToolbox", query_mxtoolbox, frozenset(IP_TYPES | {"domain", "url", "email"}), True,
             "https://mxtoolbox.com/User/Api/",
             "Registros de e-mail do domínio (MX, SPF e DMARC) e DNS reverso (PTR) de IPs.",
             "Conta gratuita: 64 consultas DNS/dia (cada domínio usa 3) e nenhuma de rede, "
             "por isso a verificação de blacklist não é usada."),
    Provider("ipinfo", "IPinfo", query_ipinfo, frozenset(IP_TYPES), True,
             "https://ipinfo.io/signup",
             "Dono do IP: ASN, organização, domínio do provedor e país.",
             "IPinfo Lite gratuito (ASN e país); o IOC Check limita a 60 consultas/min."),
]
PROVIDERS_BY_ID = {p.id: p for p in PROVIDERS}

# Indicadores usados no botão "Testar conexão" das Configurações
TEST_SAMPLES = {
    "virustotal": ("8.8.8.8", "ipv4"),
    "abuseipdb": ("8.8.8.8", "ipv4"),
    "threatfox": ("example.com", "domain"),
    "hybrid_analysis": ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256"),
    "urlscan": ("example.com", "domain"),
    "mxtoolbox": ("8.8.8.8", "ipv4"),  # PTR: gasta 1 das 64 consultas diárias, e não 3
    "ipinfo": ("8.8.8.8", "ipv4"),
}


def provider_state(provider):
    """Se a fonte está ativa, o motivo quando não está, e o consumo da cota gratuita."""
    enabled = settings.get(f"{provider.id}_enabled")
    has_key = bool(settings.get(f"{provider.id}_api_key"))
    if not enabled:
        reason = "Desativada nas configurações"
    elif provider.key_required and not has_key:
        reason = "Chave de API não configurada"
    else:
        reason = None
    return {"enabled": enabled, "has_key": has_key, "active": reason is None, "reason": reason,
            "usage": quota.usage(provider.id), "terms": provider.terms}


def source_link(provider_id, value, ioc_type):
    """Página pública da fonte já com o indicador, para abrir mesmo quando a API falha."""
    q = quote(value, safe="")
    if provider_id == "virustotal":
        return f"https://www.virustotal.com/gui/search/{q}"
    if provider_id == "abuseipdb":
        return f"https://www.abuseipdb.com/check/{q}"
    if provider_id == "threatfox":
        return f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{q}"
    if provider_id == "hybrid_analysis":
        return f"https://www.hybrid-analysis.com/search?query={q}"
    if provider_id == "urlscan":
        return f"https://urlscan.io/search/#{quote(_urlscan_query(value, ioc_type), safe='')}"
    if provider_id == "mxtoolbox":
        target, commands = _mxtoolbox_target(value, ioc_type)
        return f"https://mxtoolbox.com/SuperTool.aspx?action={commands[0]}%3a{quote(target, safe='')}&run=toolpage"
    if provider_id == "ipinfo":
        return f"https://ipinfo.io/{q}"
    return None


def _query_provider(provider, value, ioc_type, state, ignore_disabled):
    name = provider.name
    if not state["enabled"] and not ignore_disabled:
        return provider_result(name, "skipped", summary="Fonte desativada nas configurações")
    if provider.key_required and not state["has_key"]:
        return provider_result(name, "skipped", summary="Chave de API não configurada")
    paused = quota.check(provider.id)
    if paused:
        return provider_result(name, "skipped", summary=paused, transient=True)

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


def run_provider(provider, value, ioc_type, ignore_disabled=False):
    name = provider.name
    if ioc_type not in provider.types:
        return provider_result(name, "skipped", summary="Tipo de indicador não suportado por esta fonte")
    if is_private_ip(value, ioc_type):
        return provider_result(name, "skipped", summary="IP privado/reservado não é consultado")

    result = _query_provider(provider, value, ioc_type, provider_state(provider), ignore_disabled)
    # Sem resposta útil (falha, sem chave, pausa...), o link leva direto à página da fonte
    if not result.get("link"):
        result["link"] = source_link(provider.id, value, ioc_type)
    return result


def run_all(value, ioc_type):
    return [run_provider(p, value, ioc_type) for p in PROVIDERS]


def configured_providers():
    return [{"id": p.id, "name": p.name, **provider_state(p)} for p in PROVIDERS]
