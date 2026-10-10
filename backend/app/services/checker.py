"""Fluxo principal de verificação de um indicador.

1. Normaliza e identifica o tipo do indicador.
2. Procura um resultado válido no cache (a menos que force_refresh=True).
3. Se não houver, consulta a base local + provedores externos e consolida o veredito.
4. Armazena o resultado no cache com a data de armazenamento.
5. Registra a consulta no histórico (query_logs).
"""

from ..extensions import db
from ..ioc_utils import normalize, parse_input, related_host
from ..models import Ioc, QueryLog, iso
from . import cache
from .providers import VERDICT_ORDER, provider_result, run_all

SEVERITY_SCORE = {"critical": 100, "high": 85, "medium": 60, "low": 35}
SEVERITY_LABEL = {"critical": "crítica", "high": "alta", "medium": "média", "low": "baixa"}


def check_local(value, ioc_type):
    candidates = [value]
    host = related_host(value, ioc_type)
    if host:
        candidates.append(host)

    matches = Ioc.query.filter(Ioc.value.in_(candidates), Ioc.active.is_(True))
    ioc = matches.filter(Ioc.not_expired()).first()
    if ioc is None:
        expired = matches.order_by(Ioc.expires_at.desc()).first()
        if expired is not None:
            return provider_result(
                "Base local",
                "not_found",
                # A data é formatada no navegador, que conhece o fuso do usuário
                summary="Estava na base, mas o prazo de validade expirou",
                details={"ioc_id": expired.id, "expired_at": iso(expired.expires_at)},
            )
        return provider_result("Base local", "not_found", summary="Indicador não consta na base local")

    verdict = "malicious" if ioc.severity in ("critical", "high") else "suspicious"
    match = "correspondência exata" if ioc.value == value else f"domínio relacionado ({ioc.value})"
    validity = "com prazo de validade" if ioc.expires_at else "sem prazo de expiração"
    return provider_result(
        "Base local",
        "ok",
        verdict=verdict,
        score=SEVERITY_SCORE[ioc.severity],
        summary=f"Cadastrado com severidade {SEVERITY_LABEL[ioc.severity]} — {match}; {validity}",
        details={
            "ioc_id": ioc.id,
            "severity": ioc.severity,
            "tags": ioc.tag_list,
            "description": ioc.description,
            "source": ioc.source,
            "expires_at": iso(ioc.expires_at),
        },
    )


def consolidate(results):
    """Veredito final = o mais grave entre as fontes que trouxeram informação."""
    informative = [r for r in results if r["status"] == "ok"]
    if not informative:
        return "unknown", 0
    verdict = max((r["verdict"] for r in informative), key=VERDICT_ORDER.get)
    score = max(r["score"] for r in informative)
    return verdict, score


def analyze(value, ioc_type):
    results = [check_local(value, ioc_type)]
    results.extend(run_all(value, ioc_type))
    return results


def check_indicator(raw, force_refresh=False):
    value, ioc_type = normalize(raw)
    if ioc_type is None:
        return {
            "input": raw,
            "valid": False,
            "error": "Formato não reconhecido (use IP, domínio, URL, e-mail ou hash MD5/SHA1/SHA256)",
        }

    entry = None if force_refresh else cache.get_valid(value)
    from_cache = entry is not None
    if not from_cache:
        results = analyze(value, ioc_type)
        verdict, score = consolidate(results)
        entry = cache.store(value, ioc_type, verdict, score, results)

    db.session.add(
        QueryLog(
            indicator=value,
            ioc_type=ioc_type,
            verdict=entry.verdict,
            score=entry.score,
            from_cache=from_cache,
            cache_stored_at=entry.stored_at,
        )
    )

    return {
        "input": raw,
        "valid": True,
        "indicator": value,
        "type": ioc_type,
        "verdict": entry.verdict,
        "score": entry.score,
        "from_cache": from_cache,
        "stored_at": iso(entry.stored_at),
        "expires_at": iso(entry.expires_at),
        "hits": entry.hits,
        "results": entry.results,
    }


def check_many(data, force_refresh=False):
    results = [check_indicator(item, force_refresh) for item in parse_input(data)]
    db.session.commit()
    return results
