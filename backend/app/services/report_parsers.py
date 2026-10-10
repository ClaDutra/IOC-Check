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
    if data.get("numDistinctUsers") is not None:
        facts.append(fact("Denunciantes distintos", data["numDistinctUsers"]))
    if data.get("lastReportedAt"):
        facts.append(fact("Última denúncia", data["lastReportedAt"]))

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
