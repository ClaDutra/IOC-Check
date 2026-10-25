"""Leitura detalhada das respostas do URLScan.io e do AbuseIPDB.

As duas APIs devolvem muito mais do que um veredito. Aqui extraímos o que ajuda
na análise (downloads, redirecionamentos, marcas imitadas, categorias de abuso,
uso da rede Tor...) e transformamos em três listas exibidas no front-end:

  flags    -> alertas de comportamento, com nível "bad", "warn" ou "info"
  facts    -> informações de contexto (rótulo e valor)
  sections -> listas com título (ex.: arquivos baixados, cadeia de redirecionamentos)

Cada função também pode sugerir um veredito mínimo ("piso") a partir desses sinais.
"""

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit

# Tipos MIME de arquivos executáveis ou instaladores
EXECUTABLE_MIMES = {
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-mach-binary",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
    "application/x-msi",
    "application/vnd.android.package-archive",
}
EXECUTABLE_HINTS = ("executable", "pe32", "elf ", "mach-o", "ms-dos", "installer")
ARCHIVE_MIMES = {"application/zip", "application/x-rar-compressed", "application/x-7z-compressed",
                 "application/gzip", "application/x-tar", "application/vnd.rar"}

# Categorias de denúncia do AbuseIPDB (https://www.abuseipdb.com/categories)
ABUSEIPDB_CATEGORIES = {
    1: "Comprometimento de DNS", 2: "Envenenamento de DNS", 3: "Pedidos fraudulentos",
    4: "Ataque DDoS", 5: "Força bruta em FTP", 6: "Ping da morte", 7: "Phishing",
    8: "Fraude em VoIP", 9: "Proxy aberto", 10: "Spam na web", 11: "Spam de e-mail",
    12: "Spam em blogs", 13: "IP de VPN", 14: "Varredura de portas", 15: "Invasão (hacking)",
    16: "SQL Injection", 17: "Falsificação (spoofing)", 18: "Força bruta", 19: "Robô malicioso",
    20: "Host comprometido", 21: "Ataque a aplicação web", 22: "SSH", 23: "Alvo IoT",
}
HOSTING_USAGE = ("Data Center", "Web Hosting", "Transit")


def flag(text, level="warn"):
    return {"text": text, "level": level}


def fact(label, value, href=None):
    item = {"label": label, "value": str(value)}
    if href and str(href).startswith("https://"):
        item["href"] = href
    return item


def _human_size(size):
    try:
        size = float(size)
    except (TypeError, ValueError):
        return "tamanho desconhecido"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return ""


def _is_ip(host):
    try:
        ipaddress.ip_address(host or "")
        return True
    except ValueError:
        return False


def _names(items):
    """Lista de marcas/categorias pode vir como texto ou como objetos com "name"."""
    names = []
    for item in items or []:
        name = item.get("name") or item.get("key") if isinstance(item, dict) else item
        if name and str(name) not in names:
            names.append(str(name))
    return names


# --- URLScan.io -------------------------------------------------------------

def _is_executable(download):
    mime = str(download.get("mimeType") or "").lower()
    description = str(download.get("mimeDescription") or "").lower()
    return mime in EXECUTABLE_MIMES or any(hint in description for hint in EXECUTABLE_HINTS)


def _redirect_chain(report):
    """Monta a cadeia de redirecionamentos (status, origem e destino)."""
    data = report.get("data") or {}
    chain = []

    for item in data.get("redirects") or []:
        if isinstance(item, dict):
            chain.append({
                "status": item.get("status") or item.get("statusCode") or "",
                "from": item.get("from") or item.get("url") or "",
                "to": item.get("to") or item.get("location") or item.get("redirectURL") or "",
            })

    # O navegador do URLScan grava em cada requisição a resposta de redirecionamento
    # que a originou (redirectResponse); juntando-as temos a cadeia do documento principal.
    if not chain:
        for entry in data.get("requests") or []:
            steps = entry.get("requests") or [entry]
            for step in steps:
                request = step.get("request") or {}
                redirect = request.get("redirectResponse")
                if request.get("type") == "Document" and isinstance(redirect, dict):
                    chain.append({
                        "status": redirect.get("status", ""),
                        "from": redirect.get("url", ""),
                        "to": (request.get("request") or {}).get("url", ""),
                    })
    return chain


def analyze_urlscan_report(report):
    page = report.get("page") or {}
    task = report.get("task") or {}
    data = report.get("data") or {}
    lists = report.get("lists") or {}
    stats = report.get("stats") or {}
    verdicts = report.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    engines = verdicts.get("engines") or {}
    community = verdicts.get("community") or {}
    processors = (report.get("meta") or {}).get("processors") or {}
    downloads = [d for d in (processors.get("download") or {}).get("data") or [] if isinstance(d, dict)]

    flags, facts, sections = [], [], []
    verdict, score = "clean", 0
    host = urlsplit(page.get("url") or task.get("url") or "").hostname or page.get("domain")

    # Downloads: o sinal mais forte de distribuição de malware
    executables = [d for d in downloads if _is_executable(d)]
    for d in downloads:
        name = d.get("filename") or "arquivo sem nome"
        if _is_executable(d):
            flags.append(flag(f"Baixa arquivo executável: {name}", "bad"))
        elif str(d.get("mimeType") or "").lower() in ARCHIVE_MIMES:
            flags.append(flag(f"Baixa arquivo compactado: {name}", "warn"))
        else:
            flags.append(flag(f"Baixa arquivo: {name}", "warn"))
    if downloads:
        sections.append({
            "title": "Arquivos baixados pela página",
            "rows": [
                {
                    "text": f"{d.get('filename') or 'sem nome'} · {_human_size(d.get('filesize'))} · "
                            f"{d.get('mimeDescription') or d.get('mimeType') or 'tipo desconhecido'}"
                            + (f" · SHA256 {d['sha256']}" if d.get("sha256") else ""),
                    "check": d.get("sha256"),
                }
                for d in downloads
            ],
        })
    if executables:
        # Executável servido direto de um IP, ou já marcado por mecanismos, é típico de malware
        if engines.get("malicious") or _is_ip(host):
            verdict, score = "malicious", 80
        else:
            verdict, score = "suspicious", 60

    # Redirecionamentos
    chain = _redirect_chain(report)
    if chain:
        flags.append(flag(f"Redireciona {len(chain)} vez(es)", "warn"))
        sections.append({
            "title": "Cadeia de redirecionamentos",
            "rows": [{"text": f"{step['status']} {step['from']} → {step['to']}".strip()} for step in chain],
        })
    elif task.get("url") and page.get("url") and task["url"] != page["url"]:
        flags.append(flag("A URL final é diferente da URL enviada", "info"))

    # Vereditos do próprio URLScan
    brands = _names(overall.get("brands")) or _names((verdicts.get("urlscan") or {}).get("brands"))
    categories = _names(overall.get("categories"))
    if overall.get("malicious"):
        flags.append(flag(f"Classificado como malicioso pelo URLScan (score {overall.get('score', 0)})", "bad"))
        verdict, score = "malicious", max(score, 70, int(overall.get("score") or 0))
    if brands:
        flags.append(flag(f"Imita a marca: {', '.join(brands)}", "bad"))
        verdict, score = "malicious", max(score, 85)
    if categories:
        flags.append(flag(f"Categorias: {', '.join(categories)}", "warn"))
    if engines.get("malicious"):
        engine_score = int(engines.get("score") or 0)
        flags.append(flag(f"Mecanismos de detecção/IA apontam risco (score {engine_score})", "warn"))
        if verdict == "clean":
            verdict, score = "suspicious", max(score, engine_score, 40)
    votes_bad = int(community.get("votesMalicious") or 0)
    votes_good = int(community.get("votesBenign") or 0)
    if votes_bad:
        flags.append(flag(f"{votes_bad} voto(s) malicioso(s) da comunidade", "warn"))
        if votes_bad > votes_good and verdict == "clean":
            verdict, score = "suspicious", max(score, 40)

    # Contexto da página
    if str(page.get("url") or "").startswith("http://") and not stats.get("securePercentage"):
        flags.append(flag("Página sem HTTPS", "info"))
    age = page.get("apexDomainAgeDays")
    if host and not _is_ip(host) and isinstance(age, int) and 0 < age <= 30:
        flags.append(flag(f"Domínio registrado há apenas {age} dia(s)", "warn"))
    if host and _is_ip(host):
        flags.append(flag("Servido diretamente por endereço IP, sem domínio", "info"))

    if page.get("url"):
        facts.append(fact("URL final", page["url"]))
    if page.get("title"):
        facts.append(fact("Título da página", page["title"]))
    if page.get("status"):
        facts.append(fact("Status HTTP", page["status"]))
    if page.get("mimeType"):
        facts.append(fact("Tipo de conteúdo", page["mimeType"]))
    location = ", ".join(p for p in (page.get("city"), page.get("country")) if p)
    if page.get("ip"):
        facts.append(fact("IP", f"{page['ip']}" + (f" ({location})" if location else "")))
    if page.get("asnname") or page.get("asn"):
        facts.append(fact("Rede (ASN)", " · ".join(p for p in (page.get("asn"), page.get("asnname")) if p)))
    if page.get("ptr"):
        facts.append(fact("DNS reverso", page["ptr"]))
    if page.get("server"):
        facts.append(fact("Servidor", page["server"]))
    facts.append(fact("Requisições feitas", len(data.get("requests") or [])))
    facts.append(fact("Domínios / IPs contatados",
                      f"{len(lists.get('domains') or [])} / {len(lists.get('ips') or [])}"))
    if task.get("time"):
        facts.append(fact("Data da varredura", task["time"]))
    if task.get("screenshotURL"):
        facts.append(fact("Captura de tela", "abrir imagem", task["screenshotURL"]))

    return {
        "verdict": verdict,
        "score": score,
        "flags": flags,
        "facts": facts,
        "sections": sections,
        "downloads": len(downloads),
        "executables": len(executables),
        "redirects": len(chain),
    }


# --- AbuseIPDB --------------------------------------------------------------

def analyze_abuseipdb(data):
    flags, facts, sections = [], [], []

    if data.get("isTor"):
        flags.append(flag("Nó de saída da rede Tor", "warn"))
    if data.get("isWhitelisted"):
        flags.append(flag("Está na lista de permissão do AbuseIPDB", "info"))
    usage = data.get("usageType") or ""
    if any(kind in usage for kind in HOSTING_USAGE):
        flags.append(flag("Endereço de datacenter/hospedagem", "info"))

    # Contagem das categorias denunciadas (só vem com o parâmetro "verbose")
    reports = [r for r in data.get("reports") or [] if isinstance(r, dict)]
    counts = {}
    for report in reports:
        for category in report.get("categories") or []:
            counts[category] = counts.get(category, 0) + 1
    top = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:4]
    if top:
        text = ", ".join(f"{ABUSEIPDB_CATEGORIES.get(c, f'categoria {c}')} ({n})" for c, n in top)
        flags.append(flag(f"Denunciado por: {text}", "bad" if int(data.get("abuseConfidenceScore") or 0) >= 25 else "warn"))

    country = data.get("countryName") or data.get("countryCode")
    if country:
        facts.append(fact("País", country))
    if data.get("isp"):
        facts.append(fact("Provedor (ISP)", data["isp"]))
    if data.get("domain"):
        facts.append(fact("Domínio do provedor", data["domain"]))
    if data.get("hostnames"):
        facts.append(fact("Hostnames", ", ".join(data["hostnames"][:5])))
    if usage:
        facts.append(fact("Tipo de uso", usage))
    if data.get("ipVersion"):
        facts.append(fact("Versão do IP", f"IPv{data['ipVersion']}" + ("" if data.get("isPublic", True) else " (privado)")))
    facts.append(fact("Confiança de abuso", f"{int(data.get('abuseConfidenceScore') or 0)}%"))
    if data.get("totalReports") is not None:
        facts.append(fact("Denúncias em 90 dias", data["totalReports"]))
    if data.get("numDistinctUsers") is not None:
        facts.append(fact("Denunciantes distintos", data["numDistinctUsers"]))
    if data.get("lastReportedAt"):
        facts.append(fact("Última denúncia", data["lastReportedAt"]))
    dates = sorted(str(r.get("reportedAt")) for r in reports if r.get("reportedAt"))
    if dates:
        facts.append(fact("Primeira denúncia no período", dates[0]))

    # De onde vêm as denúncias: muitos países diferentes indicam ataque disseminado
    countries = {}
    for report in reports:
        name = report.get("reporterCountryName") or report.get("reporterCountryCode")
        if name:
            countries[name] = countries.get(name, 0) + 1
    if countries:
        top_countries = sorted(countries.items(), key=lambda item: item[1], reverse=True)[:5]
        facts.append(fact("Países que mais denunciaram", ", ".join(f"{c} ({n})" for c, n in top_countries)))

    recent = sorted(reports, key=lambda r: r.get("reportedAt") or "", reverse=True)[:5]
    if recent:
        rows = []
        for report in recent:
            categories = ", ".join(ABUSEIPDB_CATEGORIES.get(c, str(c)) for c in report.get("categories") or [])
            comment = " ".join(str(report.get("comment") or "").split())
            if len(comment) > 160:
                comment = comment[:157] + "..."
            date = str(report.get("reportedAt") or "")[:10]
            rows.append({"text": " · ".join(p for p in (date, categories, comment) if p)})
        sections.append({"title": "Denúncias recentes", "rows": rows})

    return {"flags": flags, "facts": facts, "sections": sections, "categories": [c for c, _ in top]}


# --- Utilidades de data -----------------------------------------------------

def _epoch_iso(value):
    """O VirusTotal envia datas como timestamp UNIX; convertemos para ISO 8601 (UTC)."""
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return None


def _days_since(value):
    try:
        return (datetime.now(timezone.utc) - datetime.fromtimestamp(int(value), timezone.utc)).days
    except (TypeError, ValueError, OSError):
        return None


# --- VirusTotal -------------------------------------------------------------

RISKY_CATEGORY_WORDS = ("phish", "malware", "malicious", "spam", "fraud", "scam")


def _vt_network_facts(attributes, facts):
    if attributes.get("as_owner"):
        facts.append(fact("Rede (ASN)", f"AS{attributes.get('asn')} · {attributes['as_owner']}"))
    if attributes.get("network"):
        facts.append(fact("Bloco de rede", attributes["network"]))
    location = " · ".join(str(p) for p in (attributes.get("country"), attributes.get("continent")) if p)
    if location:
        facts.append(fact("País / continente", location))
    if attributes.get("regional_internet_registry"):
        facts.append(fact("Registro regional", attributes["regional_internet_registry"]))


def _vt_domain_facts(attributes, flags, facts):
    if attributes.get("registrar"):
        facts.append(fact("Registrador", attributes["registrar"]))
    if attributes.get("creation_date"):
        facts.append(fact("Criado em", _epoch_iso(attributes["creation_date"])))
        age = _days_since(attributes["creation_date"])
        if age is not None and age <= 30:
            flags.append(flag(f"Domínio criado há apenas {age} dia(s)", "warn"))
    ranks = [v.get("rank") for v in (attributes.get("popularity_ranks") or {}).values()
             if isinstance(v, dict) and v.get("rank")]
    if ranks:
        flags.append(flag(f"Domínio popular (melhor posição em rankings: {min(ranks)})", "info"))
    addresses = [r.get("value") for r in attributes.get("last_dns_records") or []
                 if isinstance(r, dict) and r.get("type") in ("A", "AAAA")]
    if addresses:
        facts.append(fact("Endereços IP (DNS)", ", ".join(addresses[:5])))
    cert = attributes.get("last_https_certificate") or {}
    issuer = (cert.get("issuer") or {}).get("O") or (cert.get("issuer") or {}).get("CN")
    if issuer:
        facts.append(fact("Certificado HTTPS", f"{issuer} · válido até {(cert.get('validity') or {}).get('not_after', '?')}"))


def _vt_url_facts(attributes, flags, facts, sections):
    """Devolve True quando o VirusTotal aponta uma marca imitada (phishing)."""
    if attributes.get("title"):
        facts.append(fact("Título da página", attributes["title"]))
    if attributes.get("last_http_response_code"):
        facts.append(fact("Status HTTP", attributes["last_http_response_code"]))
    headers = {k.lower(): v for k, v in (attributes.get("last_http_response_headers") or {}).items()}
    if headers.get("content-type"):
        facts.append(fact("Tipo de conteúdo", headers["content-type"]))
    final_url = attributes.get("last_final_url")
    if final_url and attributes.get("url") and final_url != attributes["url"]:
        flags.append(flag("Redireciona para outro endereço", "warn"))
        facts.append(fact("URL final", final_url))
    chain = [str(u) for u in attributes.get("redirection_chain") or []]
    if chain:
        sections.append({"title": "Cadeia de redirecionamentos (VirusTotal)",
                         "rows": [{"text": u} for u in chain + ([final_url] if final_url else [])]})
    if attributes.get("times_submitted"):
        facts.append(fact("Vezes enviada ao VirusTotal", attributes["times_submitted"]))
    if attributes.get("first_submission_date"):
        facts.append(fact("Primeiro envio", _epoch_iso(attributes["first_submission_date"])))
    if attributes.get("outgoing_links"):
        facts.append(fact("Links para outros domínios", len(attributes["outgoing_links"])))
    brand = attributes.get("targeted_brand")
    brands = _names(brand.values() if isinstance(brand, dict) else ([brand] if brand else []))
    if brands:
        flags.append(flag(f"Imita a marca: {', '.join(brands)}", "bad"))
        return True
    return False


def _vt_file_facts(attributes, flags, facts, sections):
    for key, label in (("meaningful_name", "Nome do arquivo"), ("type_description", "Tipo")):
        if attributes.get(key):
            facts.append(fact(label, attributes[key]))
    if attributes.get("size"):
        facts.append(fact("Tamanho", _human_size(attributes["size"])))
    if attributes.get("first_submission_date"):
        facts.append(fact("Visto pela primeira vez", _epoch_iso(attributes["first_submission_date"])))
    if attributes.get("times_submitted"):
        facts.append(fact("Vezes enviado ao VirusTotal", attributes["times_submitted"]))
    names = [n for n in attributes.get("names") or [] if n][:6]
    if names:
        facts.append(fact("Outros nomes", ", ".join(names)))
    # Rótulo sugerido pelo VirusTotal (ex.: "trojan.mirai/mozi")
    label = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label")
    if label:
        flags.append(flag(f"Classificação mais comum: {label}", "bad"))
    sandboxes = [(name, v) for name, v in (attributes.get("sandbox_verdicts") or {}).items()
                 if isinstance(v, dict) and v.get("category") in ("malicious", "suspicious")]
    if sandboxes:
        rows = []
        for name, v in sandboxes:
            malware = v.get("malware_names") or v.get("malware_classification") or []
            rows.append({"text": f"{v.get('sandbox_name') or name}: {v.get('category')}"
                                 + (f" ({', '.join(map(str, malware))})" if malware else "")})
        sections.append({"title": "Veredito das sandboxes", "rows": rows})
    yara = [y for y in attributes.get("crowdsourced_yara_results") or [] if isinstance(y, dict)]
    if yara:
        sections.append({"title": "Regras YARA que identificaram o arquivo",
                         "rows": [{"text": f"{y.get('rule_name')} ({y.get('source') or y.get('ruleset_name') or 'comunidade'})"}
                                  for y in yara[:8]]})
    sigma = attributes.get("sigma_analysis_stats") or {}
    severe = int(sigma.get("critical") or 0) + int(sigma.get("high") or 0)
    if severe:
        flags.append(flag(f"{severe} regra(s) Sigma de severidade alta ou crítica", "bad"))


def analyze_virustotal(attributes, ioc_type):
    """Contexto do objeto devolvido pela API pública v3 (sem campos exclusivos do plano pago)."""
    flags, facts, sections = [], [], []
    verdict, score = None, 0

    # Quais mecanismos detectaram e com qual nome de ameaça
    detections = sorted(
        (name, r.get("result") or r.get("category"))
        for name, r in (attributes.get("last_analysis_results") or {}).items()
        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
    )
    if detections:
        sections.append({"title": f"Mecanismos que apontaram risco ({len(detections)})",
                         "rows": [{"text": f"{name}: {result}"} for name, result in detections[:15]]})

    votes = attributes.get("total_votes") or {}
    if int(votes.get("malicious") or 0):
        flags.append(flag(f"{votes['malicious']} voto(s) malicioso(s) da comunidade VirusTotal", "warn"))
    reputation = attributes.get("reputation")
    if isinstance(reputation, int) and reputation < 0:
        flags.append(flag(f"Reputação negativa na comunidade ({reputation})", "warn"))
    if attributes.get("tags"):
        facts.append(fact("Etiquetas", ", ".join(map(str, attributes["tags"][:8]))))
    if attributes.get("last_analysis_date"):
        facts.append(fact("Última análise", _epoch_iso(attributes["last_analysis_date"])))

    categories = sorted({str(c) for c in (attributes.get("categories") or {}).values()})
    if categories:
        facts.append(fact("Categorias", ", ".join(categories[:6])))
        risky = [c for c in categories if any(w in c.lower() for w in RISKY_CATEGORY_WORDS)]
        if risky:
            flags.append(flag(f"Categorizado como: {', '.join(risky[:3])}", "bad"))

    if ioc_type in IP_TYPES_LOCAL:
        _vt_network_facts(attributes, facts)
    elif ioc_type == "domain":
        _vt_domain_facts(attributes, flags, facts)
    elif ioc_type == "url":
        if _vt_url_facts(attributes, flags, facts, sections):
            verdict, score = "malicious", 85
    else:
        _vt_file_facts(attributes, flags, facts, sections)

    return {"verdict": verdict, "score": score, "flags": flags, "facts": facts, "sections": sections}


IP_TYPES_LOCAL = ("ipv4", "ipv6")


# --- ThreatFox --------------------------------------------------------------

def analyze_threatfox(entries, related=None):
    """Contexto dos registros do ThreatFox: malware, tipo de ameaça, datas e amostras."""
    flags, facts, sections = [], [], []
    related = related or []
    main = entries[0] if entries else (related[0] if related else {})

    for key, label in (("threat_type_desc", "Tipo de ameaça"), ("ioc_type_desc", "Tipo de indicador"),
                       ("malware_alias", "Também conhecido como"), ("first_seen", "Visto pela primeira vez"),
                       ("last_seen", "Visto pela última vez"), ("reporter", "Reportado por"),
                       ("sightings", "Avistamentos")):
        if main.get(key):
            facts.append(fact(label, main[key]))
    if main.get("malware_malpedia"):
        facts.append(fact("Ficha do malware (Malpedia)", main.get("malware_printable") or "abrir", main["malware_malpedia"]))
    if main.get("reference"):
        facts.append(fact("Referência", main["reference"], main["reference"]))
    tags = sorted({str(t) for e in entries + related for t in (e.get("tags") or [])})
    if tags:
        facts.append(fact("Etiquetas", ", ".join(tags[:10])))
    if any(e.get("is_compromised") for e in entries):
        flags.append(flag("Servidor legítimo comprometido (a vítima também é o host)", "info"))

    samples = [s for e in entries + related for s in (e.get("malware_samples") or []) if isinstance(s, dict)]
    if samples:
        sections.append({
            "title": "Amostras de malware ligadas ao indicador",
            "rows": [{"text": f"{str(s.get('time_stamp') or '')[:10]} · SHA256 {s['sha256_hash']}", "check": s["sha256_hash"]}
                     for s in samples[:8] if s.get("sha256_hash")],
        })
    if related:
        families = sorted({e.get("malware_printable") for e in related if e.get("malware_printable")})
        flags.append(flag(f"Hospeda {len(related)} IOC(s) de malware: {', '.join(families[:3]) or 'família não identificada'}", "bad"))
        sections.append({
            "title": "IOCs no mesmo host",
            "rows": [{"text": f"{e.get('ioc')} · {e.get('malware_printable') or '?'} · "
                              f"{e.get('threat_type_desc') or e.get('threat_type') or ''}", "check": e.get("ioc")}
                     for e in related[:8]],
        })
    return {"flags": flags, "facts": facts, "sections": sections}


# --- Hybrid Analysis --------------------------------------------------------

HYBRID_VERDICT_MAP = {"malicious": "malicious", "suspicious": "suspicious",
                      "no specific threat": "clean", "whitelisted": "clean", "no verdict": "unknown"}


def analyze_hybrid_overview(overview, reports=None):
    """Lê o /overview/{sha256}, disponível também para chaves gratuitas ("restricted")."""
    flags, facts, sections = [], [], []
    verdict = HYBRID_VERDICT_MAP.get(str(overview.get("verdict") or "").lower(), "unknown")
    multiscan = overview.get("multiscan_result") if isinstance(overview.get("multiscan_result"), (int, float)) else None
    score = overview.get("threat_score") if isinstance(overview.get("threat_score"), (int, float)) else None
    if score is None:
        score = multiscan if multiscan is not None else {"malicious": 80, "suspicious": 50}.get(verdict, 0)

    if verdict == "malicious":
        flags.append(flag("Veredito da sandbox: malicioso", "bad"))
    elif verdict == "suspicious":
        flags.append(flag("Veredito da sandbox: suspeito", "warn"))
    if overview.get("vx_family"):
        flags.append(flag(f"Família: {overview['vx_family']}", "bad"))
    if overview.get("whitelisted"):
        flags.append(flag("Arquivo na lista de confiáveis", "info"))
    reports = [r for r in reports or [] if isinstance(r, dict)]
    if reports and all(r.get("state") == "ERROR" for r in reports):
        flags.append(flag("A sandbox não conseguiu executar o arquivo (tipo não suportado pelo ambiente)", "info"))

    if overview.get("type"):
        facts.append(fact("Tipo", overview["type"]))
    if overview.get("size"):
        facts.append(fact("Tamanho", _human_size(overview["size"])))
    if multiscan is not None:
        facts.append(fact("Detecção nos antivírus", f"{multiscan}%"))
    if overview.get("last_file_name"):
        facts.append(fact("Último nome de envio", overview["last_file_name"]))
    # Ignora nomes que são só números (gerados por honeypots a partir do IP de origem)
    names = [n for n in overview.get("other_file_name") or [] if n and not n.replace(".", "").isdigit()][:6]
    if names:
        facts.append(fact("Outros nomes", ", ".join(names)))
    if overview.get("submitted_at"):
        facts.append(fact("Primeiro envio", overview["submitted_at"]))
    if overview.get("analysis_start_time"):
        facts.append(fact("Análise mais recente", overview["analysis_start_time"]))
    if overview.get("tags"):
        facts.append(fact("Etiquetas", ", ".join(map(str, overview["tags"][:8]))))
    up, down = overview.get("community_score_votes_up"), overview.get("community_score_votes_down")
    if up or down:
        facts.append(fact("Votos da comunidade", f"{up or 0} positivo(s) · {down or 0} negativo(s)"))
    if reports:
        facts.append(fact("Análises na sandbox", len(reports)))

    scanners = [v for v in (overview.get("scanners_v2") or {}).values()
                if isinstance(v, dict) and v.get("status") not in (None, "error", "no-result")]
    if scanners:
        sections.append({
            "title": "Scanners consultados pela Hybrid Analysis",
            "rows": [{"text": f"{s.get('name')}: {s.get('status')}"
                              + (f" ({s.get('positives')}/{s.get('total')})" if s.get("total") else "")} for s in scanners],
        })
    contexts = [c for c in overview.get("submit_context") or [] if isinstance(c, str)][:6]
    if contexts:
        sections.append({"title": "Endereços de onde o arquivo foi baixado",
                         "rows": [{"text": c, "check": c} for c in contexts]})
    return {"verdict": verdict, "score": int(score), "flags": flags, "facts": facts, "sections": sections}


# --- MxToolbox ------------------------------------------------------------------
# Cada comando (mx, spf, dmarc, ptr) devolve as verificações em Failed, Warnings e
# Passed, além dos registros encontrados (Information e Records).

MX_LABELS = {"mx": "MX", "spf": "SPF", "dmarc": "DMARC", "ptr": "PTR"}


def _dmarc_policy(record):
    for part in str(record or "").replace(" ", "").split(";"):
        if part.lower().startswith("p="):
            return part[2:].lower()
    return None


def analyze_mxtoolbox(lookups):
    """lookups: {comando: resposta JSON}. Devolve resumo, alertas, informações e listas."""
    flags, facts, rows, parts = [], [], [], []
    for command, data in lookups.items():
        label = MX_LABELS.get(command, command.upper())
        failed, warnings = data.get("Failed") or [], data.get("Warnings") or []
        info = [i for i in data.get("Information") or [] if isinstance(i, dict)]
        records = [str(r) for r in data.get("Records") or []]

        for item in failed:
            flags.append({"text": f"{label}: {item.get('Name', '')} — {item.get('Info', '')}", "level": "warn"})
            rows.append({"text": f"Falha · {label} · {item.get('Name', '')}: {item.get('Info', '')}"})
        for item in warnings:
            flags.append({"text": f"{label}: {item.get('Name', '')} — {item.get('Info', '')}", "level": "info"})
            rows.append({"text": f"Aviso · {label} · {item.get('Name', '')}: {item.get('Info', '')}"})
        for item in data.get("Passed") or []:
            rows.append({"text": f"OK · {label} · {item.get('Name', '')}: {item.get('Info', '')}"})

        if command == "mx":
            hosts = [i.get("Hostname") for i in info if i.get("Hostname") not in (None, "", ".")]
            if hosts:
                facts.append({"label": "Servidores MX", "value": ", ".join(hosts[:6])})
                parts.append(f"{len(hosts)} servidor(es) MX")
            else:
                parts.append("sem servidor MX (o domínio não recebe e-mail)")
        elif command == "spf":
            spf = next((r for r in records if r.lower().startswith("v=spf1")), None)
            if spf:
                facts.append({"label": "Registro SPF", "value": spf})
            parts.append("SPF publicado" if spf else "sem SPF")
        elif command == "dmarc":
            dmarc = next((r for r in records if r.upper().startswith("V=DMARC1")), None)
            policy = _dmarc_policy(dmarc)
            if dmarc:
                facts.append({"label": "Registro DMARC", "value": dmarc})
            parts.append(f"DMARC p={policy}" if policy else "sem DMARC")
            if policy == "none":
                flags.append({"text": "DMARC com política \"none\": e-mails falsificados não são bloqueados",
                              "level": "info"})
        elif command == "ptr":
            names = [i.get("Domain Name") or i.get("Hostname") or i.get("Name") for i in info]
            names = [n for n in names if n]
            if names:
                facts.append({"label": "DNS reverso (PTR)", "value": ", ".join(names[:4])})
            parts.append(f"PTR {names[0]}" if names else "sem DNS reverso (PTR)")

    sections = [{"title": "Verificações da MxToolbox", "rows": rows[:40]}] if rows else []
    return {"summary": " · ".join(parts), "flags": flags, "facts": facts, "sections": sections}


# --- IPinfo ---------------------------------------------------------------------
# IPinfo Lite (gratuito): ASN, organização dona do bloco, domínio do AS, país e continente.

def analyze_ipinfo(data):
    asn, as_name, as_domain = data.get("asn"), data.get("as_name"), data.get("as_domain")
    country, code = data.get("country"), data.get("country_code")
    facts = [f for f in (
        {"label": "ASN", "value": asn} if asn else None,
        {"label": "Organização (AS)", "value": as_name} if as_name else None,
        {"label": "Domínio do AS", "value": as_domain} if as_domain else None,
        {"label": "País", "value": f"{country} ({code})" if code else country} if country else None,
        {"label": "Continente", "value": data.get("continent")} if data.get("continent") else None,
    ) if f]
    owner = " ".join(x for x in (asn, as_name) if x)
    place = f"{country} ({code})" if country and code else (country or "")
    summary = " · ".join(x for x in (owner, f"domínio {as_domain}" if as_domain else "", place) if x)
    return {"summary": summary or "Sem informações de rede para este IP", "facts": facts}
