"""Gera "prints de evidência" (PNG) a partir dos resultados guardados no histórico.

Cada fonte vira um cartão com o indicador, o veredito, os alertas, as informações
de contexto e as listas de detalhes, no estilo das páginas das próprias fontes.
Fotografar as páginas web das fontes não é permitido nos planos gratuitos
(o AbuseIPDB limita as páginas detalhadas a 10 por dia e o VirusTotal proíbe
acesso automatizado à interface), por isso a evidência é montada com os dados
que as APIs devolveram. A exceção é o URLScan.io, cuja API fornece a captura de
tela real da página, que é incluída no cartão.
"""

import io
import os
from datetime import timezone
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

from ..ioc_utils import TYPE_LABELS
from . import media as media_store
from .providers import VERDICT_ORDER

# Marca d'água com o endereço do projeto no GitHub, em todos os prints e textos de evidência
WATERMARK = "github.com/ClaDutra/IOC-Check"

# A base local é do próprio analista: os prints de evidência mostram só as ferramentas externas
LOCAL_SOURCE = "Base local"


def tool_results(entry):
    return [r for r in entry.results if r.get("provider") != LOCAL_SOURCE]


def tool_verdict(results):
    """Veredito e score considerando só as ferramentas (sem a base local)."""
    informative = [r for r in results if r.get("status") == "ok"]
    if not informative:
        return "unknown", 0
    verdict = max((r.get("verdict", "unknown") for r in informative), key=lambda v: VERDICT_ORDER.get(v, 0))
    return verdict, max(int(r.get("score") or 0) for r in informative)

WIDTH = 1200
PAD = 40
INNER = WIDTH - 2 * PAD

INK = (30, 32, 44)
GRAPHITE = (49, 50, 62)
PURPLE = (96, 81, 155)
LAVENDER = (191, 192, 209)
MUTED = (110, 112, 130)
LINE = (231, 231, 239)
PANEL_2 = (244, 244, 249)
WHITE = (255, 255, 255)

VERDICT_STYLE = {
    "malicious": ("Malicioso", (214, 69, 69), (251, 233, 233)),
    "suspicious": ("Suspeito", (154, 106, 10), (251, 241, 220)),
    "clean": ("Limpo", (31, 122, 86), (226, 245, 236)),
    "unknown": ("Sem veredito", GRAPHITE, (238, 238, 244)),
}
STATUS_LABEL = {"ok": "Analisado", "not_found": "Sem registro", "skipped": "Não consultado", "error": "Erro"}
FLAG_STYLE = {
    "bad": ((180, 47, 47), (251, 233, 233)),
    "warn": ((154, 106, 10), (251, 241, 220)),
    "info": (PURPLE, (239, 237, 247)),
}

# Fontes do sistema (Windows e Linux); se nenhuma existir, usa a fonte embutida do Pillow
FONT_FILES = {
    "regular": ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"],
    "bold": ["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"],
    "mono": ["consola.ttf", "DejaVuSansMono.ttf"],
    "mono_bold": ["consolab.ttf", "DejaVuSansMono-Bold.ttf"],
}
FONT_DIRS = [os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts"),
             "/usr/share/fonts/truetype/dejavu", "/Library/Fonts", "/System/Library/Fonts/Supplemental"]


@lru_cache(maxsize=64)
def font(size, style="regular"):
    for name in FONT_FILES[style]:
        for folder in FONT_DIRS:
            path = os.path.join(folder, name)
            if os.path.exists(path):
                return ImageFont.truetype(path, size)
    return ImageFont.load_default(size)


def _wrap(draw, text, fnt, width):
    """Quebra o texto em linhas que caibam na largura (palavras longas são cortadas)."""
    lines = []
    for paragraph in str(text).split("\n"):
        line = ""
        for word in paragraph.split(" "):
            candidate = f"{line} {word}".strip()
            if draw.textlength(candidate, font=fnt) <= width:
                line = candidate
                continue
            if line:
                lines.append(line)
            while draw.textlength(word, font=fnt) > width:  # URLs e hashes sem espaços
                cut = len(word)
                while cut > 1 and draw.textlength(word[:cut], font=fnt) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
    return lines


def _fetch_image(url):
    """Captura de tela do URLScan.io: a cópia local guardada na consulta, ou baixa agora."""
    return media_store.get(url)


def _local(dt):
    """Data do banco (UTC) no fuso do computador, que é onde o IOC Check roda."""
    return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")


class Card:
    """Desenha de cima para baixo numa imagem alta e recorta no fim."""

    def __init__(self, height=6000):
        self.image = Image.new("RGB", (WIDTH, height), WHITE)
        self.draw = ImageDraw.Draw(self.image)
        self.y = 0

    def text(self, value, x=PAD, size=20, style="regular", color=INK, width=INNER, spacing=6):
        fnt = font(size, style)
        for line in _wrap(self.draw, value, fnt, width):
            self.draw.text((x, self.y), line, font=fnt, fill=color)
            self.y += size + spacing
        return self

    def gap(self, value):
        self.y += value
        return self

    def rule(self):
        self.draw.line((PAD, self.y, WIDTH - PAD, self.y), fill=LINE, width=2)
        self.y += 2
        return self

    def pill(self, x, y, label, fg, bg, size=18):
        fnt = font(size, "bold")
        w = self.draw.textlength(label, font=fnt) + 28
        self.draw.rounded_rectangle((x, y, x + w, y + size + 16), radius=(size + 16) // 2, fill=bg)
        self.draw.text((x + 14, y + 7), label, font=fnt, fill=fg)
        return x + w

    def flags(self, flags):
        """Alertas em "etiquetas" coloridas que quebram linha quando não cabem."""
        fnt = font(17)
        x, line_h = PAD, 35
        for f in flags:
            fg, bg = FLAG_STYLE.get(f.get("level"), FLAG_STYLE["info"])
            label = "● " + str(f.get("text", ""))
            if self.draw.textlength(label, font=fnt) + 28 > INNER:
                label = _wrap(self.draw, label, fnt, INNER - 60)[0] + "…"
            w = self.draw.textlength(label, font=fnt) + 28
            if x + w > WIDTH - PAD:
                x, self.y = PAD, self.y + line_h + 8
            self.draw.rounded_rectangle((x, self.y, x + w, self.y + line_h), radius=10, fill=bg)
            self.draw.text((x + 14, self.y + 7), label, font=fnt, fill=fg)
            x += w + 10
        self.y += line_h + 4
        return self

    def facts(self, facts):
        """Tabela de informações em duas colunas, como nas páginas das fontes."""
        label_w, line_h = 300, 26
        rows = []
        for f in facts:
            value = str(f.get("value", ""))
            if f.get("href") and value in ("abrir", "abrir imagem"):
                value = f["href"]
            rows.append((_wrap(self.draw, f.get("label", ""), font(18, "bold"), label_w - 30),
                         _wrap(self.draw, value, font(18), INNER - label_w - 30)))
        height = 32 + sum(max(len(lab), len(val)) * line_h + 10 for lab, val in rows)
        self.draw.rounded_rectangle((PAD, self.y, PAD + INNER, self.y + height), radius=14, fill=PANEL_2)
        y = self.y + 16
        for labels, values in rows:
            for i, line in enumerate(labels):
                self.draw.text((PAD + 20, y + i * line_h), line, font=font(18, "bold"), fill=INK)
            for i, line in enumerate(values):
                self.draw.text((PAD + label_w, y + i * line_h), line, font=font(18), fill=GRAPHITE)
            y += max(len(labels), len(values)) * line_h + 10
        self.y += height
        return self

    def section(self, section):
        self.text(section.get("title", ""), size=19, style="bold").gap(4)
        rows = section.get("rows") or []
        for row in rows[:10]:
            start = self.y
            self.draw.text((PAD + 8, start), "•", font=font(18, "bold"), fill=PURPLE)
            self.text(row.get("text", ""), x=PAD + 30, size=17, color=GRAPHITE, width=INNER - 30, spacing=5)
            self.y += 3
        if len(rows) > 10:
            self.text(f"… e mais {len(rows) - 10} item(ns)", x=PAD + 30, size=16, color=MUTED)
        return self.gap(10)

    def screenshot(self, media):
        data = _fetch_image(media.get("url"))
        if not data:
            return self.text("O URLScan.io não guardou a captura desta varredura (comum quando o endereço "
                             "só baixa um arquivo em vez de exibir uma página).", size=16, color=MUTED).gap(8)
        shot = Image.open(io.BytesIO(data)).convert("RGB")
        shot.thumbnail((INNER, 640))
        self.text(media.get("caption") or "Captura de tela", size=17, style="bold").gap(4)
        self.image.paste(shot, (PAD, self.y))
        self.draw.rectangle((PAD, self.y, PAD + shot.width - 1, self.y + shot.height - 1), outline=LAVENDER, width=2)
        self.y += shot.height + 14
        return self

    def finish(self):
        self.y += PAD // 2
        return watermark(self.image.crop((0, 0, WIDTH, self.y)))


def watermark(image, opacity=22):
    """Marca d'água discreta: o endereço do projeto repetido na diagonal + selo no canto."""
    base = image.convert("RGBA")
    fnt = font(26, "bold")
    probe = ImageDraw.Draw(base)
    tw = int(probe.textlength(WATERMARK, font=fnt)) + 140
    tile = Image.new("RGBA", (tw, 170), (0, 0, 0, 0))
    ImageDraw.Draw(tile).text((20, 60), WATERMARK, font=fnt, fill=(96, 81, 155, opacity))
    tile = tile.rotate(24, expand=True)
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    for y in range(-tile.height, base.height + tile.height, tile.height - 40):
        offset = (y // max(tile.height - 40, 1)) % 2 * (tile.width // 2)
        for x in range(-tile.width + offset, base.width + tile.width, tile.width):
            layer.paste(tile, (x, y), tile)
    # selo legível no canto inferior direito
    seal_font = font(15, "bold")
    sw = int(probe.textlength(WATERMARK, font=seal_font))
    seal = ImageDraw.Draw(layer)
    x0, y0 = base.width - sw - 30, base.height - 34
    seal.rounded_rectangle((x0 - 10, y0 - 6, x0 + sw + 10, y0 + 22), radius=8, fill=(30, 32, 44, 170))
    seal.text((x0, y0), WATERMARK, font=seal_font, fill=(255, 255, 255, 235))
    return Image.alpha_composite(base, layer).convert("RGB")


def _header(card, entry, title):
    card.draw.rectangle((0, 0, WIDTH, 78), fill=INK)
    card.draw.rounded_rectangle((PAD, 18, PAD + 42, 60), radius=10, fill=PURPLE)
    # Escudo do logo do IOC Check
    cx = PAD + 21
    card.draw.polygon([(cx, 25), (cx + 12, 30), (cx + 12, 40), (cx, 53), (cx - 12, 40), (cx - 12, 30)],
                      outline=WHITE, width=3)
    card.draw.text((PAD + 58, 22), "IOC Check · Evidência", font=font(26, "bold"), fill=WHITE)
    tw = card.draw.textlength(title, font=font(22, "bold"))
    card.draw.text((WIDTH - PAD - tw, 26), title, font=font(22, "bold"), fill=LAVENDER)
    card.y = 104
    card.text(entry.indicator, size=30, style="mono_bold")
    card.text(f"{TYPE_LABELS.get(entry.ioc_type, entry.ioc_type)} · consultado em {_local(entry.stored_at)}",
              size=17, color=MUTED).gap(12)


def _source_block(card, result):
    label, fg, bg = VERDICT_STYLE.get(result.get("verdict"), VERDICT_STYLE["unknown"])
    status = STATUS_LABEL.get(result.get("status"), result.get("status"))
    y = card.y
    card.draw.text((PAD, y + 4), result.get("provider", ""), font=font(26, "bold"), fill=INK)
    x = PAD + card.draw.textlength(result.get("provider", ""), font=font(26, "bold")) + 18
    x = card.pill(x, y, status, PURPLE, (239, 237, 247)) + 10
    if result.get("status") == "ok":
        x = card.pill(x, y, label, fg, bg) + 10
        score = int(result.get("score") or 0)
        bar_x = WIDTH - PAD - 260
        card.draw.rounded_rectangle((bar_x, y + 14, bar_x + 200, y + 24), radius=5, fill=LINE)
        card.draw.rounded_rectangle((bar_x, y + 14, bar_x + max(10, 2 * score), y + 24), radius=5, fill=fg)
        card.draw.text((bar_x + 212, y + 4), f"{score}/100", font=font(20, "bold"), fill=INK)
    card.y = y + 52
    card.text(result.get("summary", ""), size=20, color=GRAPHITE).gap(6)
    if result.get("flags"):
        card.flags(result["flags"]).gap(8)
    for media in result.get("media") or []:
        if media.get("type") == "image":
            card.screenshot(media)
    if result.get("facts"):
        card.facts(result["facts"]).gap(14)
    for section in result.get("sections") or []:
        card.section(section)
    if result.get("link"):
        card.text(f"Fonte: {result['link']}", size=15, color=PURPLE)


def _footer(card):
    card.gap(10).rule().gap(10)
    card.text("Imagem gerada pelo IOC Check a partir das respostas das APIs públicas das fontes "
              "(planos gratuitos). Os dados refletem o momento da consulta indicado acima.", size=14, color=MUTED)
    card.gap(30)  # espaço para o selo da marca d'água


def render_source(entry, result):
    card = Card()
    _header(card, entry, result.get("provider", "Fonte"))
    _source_block(card, result)
    _footer(card)
    return card.finish()


def render_all(entry):
    """Evidência completa: veredito e dados de todas as ferramentas que responderam (sem a base local)."""
    card = Card(height=20000)
    _header(card, entry, "Todas as fontes")
    results = tool_results(entry)
    verdict, score = tool_verdict(results)
    label, fg, bg = VERDICT_STYLE.get(verdict, VERDICT_STYLE["unknown"])
    end = card.pill(PAD, card.y, f"Veredito das ferramentas: {label}", fg, bg, size=20)
    card.draw.text((end + 16, card.y + 8), f"Score {score}/100", font=font(20, "bold"), fill=INK)
    card.gap(56)
    shown = [r for r in results if r.get("status") in ("ok", "not_found")]
    skipped = [r for r in results if r not in shown]
    for result in shown:
        card.rule().gap(18)
        _source_block(card, result)
        card.gap(10)
    if skipped:
        card.rule().gap(14)
        card.text("Não consultadas: " + "; ".join(f"{r['provider']} ({r.get('summary', '')})" for r in skipped),
                  size=15, color=MUTED)
    _footer(card)
    return card.finish()


def to_png(image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


# --- Evidência em texto -------------------------------------------------------
# Mesmo conteúdo dos prints, em texto simples, para colar em tickets, e-mails e relatórios.

STATUS_TEXT = {"ok": "Analisado", "not_found": "Sem registro", "skipped": "Não consultado", "error": "Erro"}
FLAG_TEXT = {"bad": "[!]", "warn": "[atenção]", "info": "[i]"}


def _text_header(entry, title):
    return [
        f"IOC Check · Evidência · {title}",
        "=" * 60,
        f"Indicador: {entry.indicator}",
        f"Tipo: {TYPE_LABELS.get(entry.ioc_type, entry.ioc_type)}",
        f"Consultado em: {_local(entry.stored_at)}",
    ]


def _text_source(result):
    label = VERDICT_STYLE.get(result.get("verdict"), VERDICT_STYLE["unknown"])[0]
    lines = ["", f"## {result.get('provider', '')}",
             f"Status: {STATUS_TEXT.get(result.get('status'), result.get('status'))}"]
    if result.get("status") == "ok":
        lines.append(f"Veredito: {label} · score {int(result.get('score') or 0)}/100")
    if result.get("summary"):
        lines.append(f"Resumo: {result['summary']}")
    if result.get("flags"):
        lines.append("Alertas:")
        lines += [f"  {FLAG_TEXT.get(f.get('level'), '-')} {f.get('text', '')}" for f in result["flags"]]
    if result.get("facts"):
        lines.append("Informações:")
        lines += [f"  {f.get('label')}: {f.get('value')}" for f in result["facts"]]
    for section in result.get("sections") or []:
        lines.append(f"{section.get('title')}:")
        lines += [f"  - {row.get('text', '')}" for row in section.get("rows") or []]
    for item in result.get("media") or []:
        if item.get("type") == "image":
            lines.append(f"Captura de tela: {item.get('url')}")
    if result.get("link"):
        lines.append(f"Fonte: {result['link']}")
    return lines


def _text_footer():
    return ["", "-" * 60,
            "Gerado pelo IOC Check a partir das respostas das APIs públicas das fontes (planos gratuitos).",
            f"Projeto: https://{WATERMARK}"]


def text_source(entry, result):
    return "\n".join(_text_header(entry, result.get("provider", "Fonte")) + _text_source(result) + _text_footer())


def text_all(entry):
    results = tool_results(entry)
    verdict, score = tool_verdict(results)
    label = VERDICT_STYLE.get(verdict, VERDICT_STYLE["unknown"])[0]
    lines = _text_header(entry, "Todas as fontes") + [f"Veredito das ferramentas: {label} · score {score}/100"]
    shown = [r for r in results if r.get("status") in ("ok", "not_found")]
    for result in shown:
        lines += _text_source(result)
    skipped = [r for r in results if r not in shown]
    if skipped:
        lines += ["", "Não consultadas:"] + [
            f"  - {r['provider']}: {r.get('summary', '')}" + (f" ({r['link']})" if r.get("link") else "")
            for r in skipped]
    return "\n".join(lines + _text_footer())
