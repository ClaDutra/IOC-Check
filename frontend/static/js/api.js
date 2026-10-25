// Funções compartilhadas por todas as páginas: chamadas à API, formatação e componentes.

const API = {
  async request(method, url, body) {
    // X-Requested-With é exigido pelo servidor em toda requisição que altera dados
    const options = {
      method,
      headers: { Accept: "application/json", "X-Requested-With": "IOCCheck" },
      credentials: "same-origin",
    };
    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    let data = null;
    try {
      data = await response.json();
    } catch (_) {
      data = null;
    }

    if (!response.ok) {
      throw new Error((data && data.error) || `Erro ${response.status}`);
    }
    return data;
  },
  get(url) { return this.request("GET", url); },
  post(url, body) { return this.request("POST", url, body ?? {}); },
  put(url, body) { return this.request("PUT", url, body); },
  del(url) { return this.request("DELETE", url); },
};

const VERDICTS = {
  malicious: { label: "Malicioso", cls: "bad" },
  suspicious: { label: "Suspeito", cls: "warn" },
  clean: { label: "Limpo", cls: "good" },
  unknown: { label: "Desconhecido", cls: "neutral" },
};

const SEVERITIES = {
  critical: { label: "Crítica", cls: "bad" },
  high: { label: "Alta", cls: "bad" },
  medium: { label: "Média", cls: "warn" },
  low: { label: "Baixa", cls: "neutral" },
};

const TYPES = {
  ipv4: "IPv4", ipv6: "IPv6", domain: "Domínio", url: "URL",
  email: "E-mail", md5: "MD5", sha1: "SHA1", sha256: "SHA256",
};

const STATUSES = {
  ok: { label: "Analisado", cls: "info" },
  not_found: { label: "Sem registro", cls: "neutral" },
  skipped: { label: "Não consultado", cls: "neutral" },
  error: { label: "Erro", cls: "bad" },
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function badge(map, key) {
  const item = map[key] || { label: key, cls: "neutral" };
  return `<span class="badge ${item.cls}">${escapeHtml(item.label)}</span>`;
}

const verdictBadge = (v) => badge(VERDICTS, v);
const severityBadge = (s) => badge(SEVERITIES, s);
const statusBadge = (s) => badge(STATUSES, s);
const typeLabel = (t) => TYPES[t] || t;

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "medium" });
}

function relativeTime(iso) {
  if (!iso) return "";
  const diff = (new Date(iso) - Date.now()) / 1000;
  const units = [["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
  const rtf = new Intl.RelativeTimeFormat("pt-BR", { numeric: "auto" });
  for (const [unit, seconds] of units) {
    if (Math.abs(diff) >= seconds || unit === "second") {
      return rtf.format(Math.round(diff / seconds), unit);
    }
  }
  return "";
}

let toastTimer;
function toast(message, type = "info") {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = `toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3500);
}

// Converte os campos de um <form> em query string, ignorando vazios.
function formQuery(form, extra = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form)) {
    if (String(value).trim()) params.set(key, String(value).trim());
  }
  for (const [key, value] of Object.entries(extra)) params.set(key, value);
  return params.toString();
}

function renderPagination(container, data, onChange) {
  if (!data || data.pages <= 1) {
    container.innerHTML = data && data.total ? `<span>${data.total} registro(s)</span>` : "";
    return;
  }
  container.innerHTML = `
    <button class="btn btn-sm" data-page="${data.page - 1}" ${data.page <= 1 ? "disabled" : ""}>Anterior</button>
    <span>Página ${data.page} de ${data.pages} · ${data.total} registro(s)</span>
    <button class="btn btn-sm" data-page="${data.page + 1}" ${data.page >= data.pages ? "disabled" : ""}>Próxima</button>`;
  container.querySelectorAll("button[data-page]").forEach((btn) =>
    btn.addEventListener("click", () => onChange(Number(btn.dataset.page)))
  );
}

// Linhas da tabela "fonte por fonte", usada na verificação e nos detalhes do histórico.
// historyId identifica a consulta, usada nos prints de evidência e de página.
function providerRows(results, historyId, captures = {}) {
  return results
    .map((r) => {
      const link = r.link && /^https:\/\//.test(r.link)
        ? `<a class="provider-link" href="${escapeHtml(r.link)}" target="_blank" rel="noopener">ver na fonte ↗</a>`
        : "";
      const details = r.details || {};
      let validity = "";
      if (details.expires_at) validity = ` (até ${formatDay(details.expires_at)})`;
      if (details.expired_at) validity = ` em ${formatDay(details.expired_at)}`;
      const extras = providerDetails(r);
      return `
        <tr class="${extras ? "has-extras" : ""}">
          <td class="nowrap"><span class="provider-name">${sourceIcon(r.provider)}<strong>${escapeHtml(r.provider)}</strong></span></td>
          <td>${r.transient ? '<span class="badge warn">Limite gratuito</span>' : statusBadge(r.status)}</td>
          <td>${r.status === "ok" ? verdictBadge(r.verdict) : "—"}</td>
          <td>${escapeHtml(r.summary)}${escapeHtml(validity)}${link}${providerFlags(r)}${providerMedia(r)}${pageCaptureBlock(historyId, r, captures[r.provider])}${evidenceButtons(historyId, r)}</td>
        </tr>
        ${extras ? `<tr class="extras-row"><td colspan="4">${extras}</td></tr>` : ""}`;
    })
    .join("");
}

// Tudo abaixo vem de APIs externas, então todo texto passa por escapeHtml.

// Captura de tela da página (URLScan.io). Só aceita imagens do próprio URLScan.io.
const MEDIA_ORIGINS = ["https://urlscan.io/screenshots/"];

function providerMedia(r) {
  const images = (r.media || []).filter(
    (m) => m.type === "image" && MEDIA_ORIGINS.some((origin) => String(m.url).startsWith(origin))
  );
  return images
    .map((m) => {
      const target = m.link && /^https:\/\//.test(m.link) ? m.link : m.url;
      // Cópia local guardada na consulta: continua aparecendo mesmo se o site remover a imagem
      const src = `/api/evidence/screenshot?url=${encodeURIComponent(m.url)}`;
      return `
        <figure class="screenshot">
          <a href="${escapeHtml(src)}" target="_blank" rel="noopener" title="Abrir a imagem em tamanho real">
            <img src="${escapeHtml(src)}" alt="${escapeHtml(m.caption || "Captura de tela")}" loading="lazy"
                 onerror="this.closest('figure').classList.add('missing')">
          </a>
          <figcaption>${escapeHtml(m.caption || "")} ·
            <a href="${escapeHtml(target)}" target="_blank" rel="noopener">relatório completo ↗</a></figcaption>
          <p class="screenshot-missing small muted">O URLScan.io não guardou a captura desta varredura.</p>
        </figure>`;
    })
    .join("");
}

// Alertas de comportamento, sempre visíveis ao lado do resumo da fonte.
function providerFlags(r) {
  const flags = r.flags || [];
  if (!flags.length) return "";
  return `<div class="flags">${flags
    .map((f) => `<span class="flag ${escapeHtml(f.level)}">${escapeHtml(f.text)}</span>`)
    .join("")}</div>`;
}

// Informações e listas extras, recolhidas em "Mais detalhes" numa linha própria.
function providerDetails(r) {
  const facts = r.facts || [];
  const sections = r.sections || [];
  if (!facts.length && !sections.length) return "";

  const factsHtml = facts.length
    ? `<div class="facts">${facts.map((f) => `
        <div class="fact">
          <span>${escapeHtml(f.label)}</span>
          <strong>${f.href && /^https:\/\//.test(f.href)
            ? `<a href="${escapeHtml(f.href)}" target="_blank" rel="noopener">${escapeHtml(f.value)} ↗</a>`
            : escapeHtml(f.value)}</strong>
        </div>`).join("")}</div>`
    : "";
  const sectionsHtml = sections.map((s) => `
    <div class="extra-section">
      <h4>${escapeHtml(s.title)}</h4>
      <ul>${(s.rows || []).map((row) => `
        <li>${escapeHtml(row.text)}${row.check
          ? ` <a class="provider-link" href="/check?q=${encodeURIComponent(row.check)}">verificar ↗</a>`
          : ""}</li>`).join("")}</ul>
    </div>`).join("");
  return `<details class="extras"><summary>Mais detalhes de ${escapeHtml(r.provider)}</summary>${factsHtml}${sectionsHtml}</details>`;
}

function emptyRow(colspan, message) {
  return `<tr><td colspan="${colspan}" class="empty">${escapeHtml(message)}</td></tr>`;
}

// --- Validade dos IOCs -------------------------------------------------------

const EXPIRATION_PRESETS = [[7, "7 dias"], [30, "30 dias"], [90, "90 dias"], [180, "6 meses"], [365, "1 ano"]];

// Opções do <select> de validade. "keep" (edição) e "default" (cadastro) não
// enviam o campo; "never" envia null; números são dias a partir de agora.
function expirationOptions({ defaultDays, current, custom = true } = {}) {
  let first;
  if (current !== undefined) {
    first = `<option value="keep">Manter (${current ? `expira em ${formatDay(current)}` : "nunca expira"})</option>`;
  } else if (defaultDays === undefined) {
    first = '<option value="default">Validade padrão</option>';
  } else {
    first = `<option value="default">Padrão (${defaultDays ? `${defaultDays} dias` : "nunca expira"})</option>`;
  }
  return first
    + EXPIRATION_PRESETS.map(([days, label]) => `<option value="${days}">${label}</option>`).join("")
    + '<option value="never">Nunca expira</option>'
    + (custom ? '<option value="custom">Escolher data…</option>' : "");
}

// Converte a escolha em valor para a API (undefined = não enviar o campo).
function expirationValue(choice, customDate) {
  if (choice === "keep" || choice === "default") return undefined;
  if (choice === "never") return null;
  if (choice === "custom") {
    if (!customDate) throw new Error("Escolha a data de expiração");
    const [y, m, d] = customDate.split("-").map(Number);
    return new Date(y, m - 1, d, 23, 59, 59).toISOString(); // fim do dia, no fuso local
  }
  return new Date(Date.now() + Number(choice) * 86400000).toISOString();
}

function formatDay(iso) {
  return new Date(iso).toLocaleDateString("pt-BR");
}

function expirationCell(ioc) {
  if (!ioc.expires_at) return '<span class="muted">Nunca expira</span>';
  const days = (new Date(ioc.expires_at) - Date.now()) / 86400000;
  const cls = ioc.expired ? "bad" : days <= 7 ? "warn" : "";
  return `<span class="${cls ? `text-${cls}` : ""}">${formatDay(ioc.expires_at)}</span>
          <br><span class="muted small">${relativeTime(ioc.expires_at)}</span>`;
}

// Ações que apagam dados em massa: pede confirmação e chama DELETE na rota.
async function clearData(url, question, onDone) {
  if (!confirm(question)) return;
  try {
    const data = await API.del(url);
    toast(data.message, "success");
    if (onDone) onDone(data);
  } catch (err) {
    toast(err.message, "error");
  }
}

// --- Prints de evidência -----------------------------------------------------

function evidenceUrl(historyId, provider) {
  const query = provider ? `?provider=${encodeURIComponent(provider)}` : "";
  return `/api/evidence/${historyId}.png${query}`;
}

// Botões de evidência de uma fonte (só para fontes que responderam)
function evidenceButtons(historyId, r) {
  // A base local não entra nos prints de evidência: eles mostram só as ferramentas
  if (!historyId || r.provider === "Base local" || !["ok", "not_found"].includes(r.status)) return "";
  const url = evidenceUrl(historyId, r.provider);
  return evidenceActions(url, "resumo");
}

// Botões de uma evidência: copiar/baixar a imagem e, quando houver, a mesma evidência em texto.
// Os prints de evidência (/api/evidence/<id>.png) têm sempre a versão .txt correspondente.
function evidenceActions(url, label, primary = false, textUrl = undefined) {
  const sep = url.includes("?") ? "&" : "?";
  if (textUrl === undefined && /^\/api\/evidence\/\d+\.png/.test(url)) textUrl = url.replace(".png", ".txt");
  const tsep = textUrl && textUrl.includes("?") ? "&" : "?";
  const text = textUrl ? `
      <button type="button" class="btn btn-sm" data-copy-text="${escapeHtml(textUrl)}"
              title="Copia a evidência em texto simples, para colar em tickets, e-mails e relatórios">📝 Copiar texto</button>
      <a class="btn btn-sm btn-ghost" href="${escapeHtml(textUrl + tsep)}download=1" title="Baixar a evidência em texto (TXT)">⬇ TXT</a>` : "";
  return `
    <div class="evidence-actions${primary ? " primary" : ""}">
      <button type="button" class="btn btn-sm${primary ? " btn-primary" : ""}" data-copy-evidence="${escapeHtml(url)}"
              title="Copia a imagem para colar com Ctrl+V em documentos, e-mails ou chats">📋 Copiar ${escapeHtml(label)}</button>
      <a class="btn btn-sm" href="${escapeHtml(url + sep)}download=1" title="Baixar a imagem (PNG)">⬇ PNG</a>${text}
      <a class="btn btn-sm btn-ghost" href="${escapeHtml(url)}" target="_blank" rel="noopener" title="Abrir a imagem em nova aba">Ver</a>
    </div>`;
}

async function copyTextEvidence(url, button) {
  const original = button.textContent;
  button.disabled = true;
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || `Erro ${response.status}`);
    await navigator.clipboard.writeText(await response.text());
    toast("Evidência em texto copiada! Cole com Ctrl+V.", "success");
  } catch (err) {
    toast(err.message || "Não deu para copiar o texto", "error");
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy-text]");
  if (button) copyTextEvidence(button.dataset.copyText, button);
});

// Copia o PNG para a área de transferência. A promessa é passada direto ao
// ClipboardItem para o navegador manter a permissão do clique durante o download.
async function copyEvidence(url, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Gerando print…";
  try {
    const blob = fetch(url).then((response) => {
      if (!response.ok) throw new Error(`Erro ${response.status}`);
      return response.blob();
    });
    await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
    toast("Print copiado! Cole com Ctrl+V onde quiser.", "success");
  } catch (err) {
    window.open(url, "_blank", "noopener");
    toast("Não deu para copiar direto: a imagem abriu em nova aba (botão direito → Copiar imagem).", "error");
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy-evidence]");
  if (button) copyEvidence(button.dataset.copyEvidence, button);
});

// --- Print da página da fonte ----------------------------------------------

// Mesmos sites aceitos pelo servidor (services/page_capture.py)
const CAPTURE_HOSTS = ["www.virustotal.com", "www.abuseipdb.com", "threatfox.abuse.ch",
                       "www.hybrid-analysis.com", "urlscan.io", "ipinfo.io"];

function canCapture(r) {
  try {
    const url = new URL(r.link);
    return url.protocol === "https:" && CAPTURE_HOSTS.includes(url.hostname);
  } catch (_) {
    return false;
  }
}

// Prints de página seguem o prazo do cache: dentro dele, são reaproveitados nas novas consultas
function captureValidity(capture) {
  if (!capture.expires_at) return "";
  if (capture.expired) return " · fora do prazo do cache (tire um novo print para atualizar)";
  const reused = capture.reused_from ? "reaproveitado do cache, " : "";
  return ` · ${reused}válido até ${escapeHtml(formatDate(capture.expires_at))}`;
}

function captureContent(capture, provider) {
  if (!capture) return "";
  const url = capture.image;
  const sep = url.includes("?") ? "&" : "?";
  return `
    <figure class="screenshot page-shot">
      <a href="${escapeHtml(url)}" target="_blank" rel="noopener" title="Abrir o print em tamanho real">
        <img src="${escapeHtml(url + sep)}v=${encodeURIComponent(capture.captured_at)}" alt="Print da página de ${escapeHtml(provider)}" loading="lazy">
      </a>
      <figcaption>Página de ${escapeHtml(provider)} ${capture.manual ? "(print manual) " : ""}capturada em ${escapeHtml(formatDate(capture.captured_at))}${captureValidity(capture)}</figcaption>
    </figure>
    ${evidenceActions(url, "print da página", false, capture.text || null)}`;
}

function hasPublicLink(r) {
  try {
    return r.provider !== "Base local" && new URL(r.link).protocol === "https:";
  } catch (_) {
    return false;
  }
}

// Bloco de print da página: automático (quando o site permite) ou manual — o usuário abre a
// página no próprio navegador, tira o print (Win+Shift+S) e cola ou envia aqui.
function pageCaptureBlock(historyId, r, capture) {
  if (!historyId || !hasPublicLink(r)) return "";
  const auto = canCapture(r) ? `
        <button type="button" class="btn btn-sm btn-primary" data-capture-page>
          📸 ${capture ? "Novo print automático" : "Print da página"}
        </button>` : "";
  return `
    <div class="page-capture" data-entry="${historyId}" data-provider="${escapeHtml(r.provider)}"
         title="Você também pode arrastar uma imagem para cá">
      <div class="capture-buttons">${auto}
        <a class="btn btn-sm" href="${escapeHtml(r.link)}" target="_blank" rel="noopener"
           title="Abre a página no seu navegador normal; tire o print com Win+Shift+S">🌐 Abrir no meu navegador</a>
        <button type="button" class="btn btn-sm" data-paste-capture
                title="Cola o print que está na área de transferência (Win+Shift+S)">📋 Colar print</button>
        <label class="btn btn-sm" title="Escolher um arquivo de imagem (PNG, JPG, WebP)">⬆ Enviar imagem
          <input type="file" accept="image/png,image/jpeg,image/webp,image/bmp,image/gif" data-upload-capture hidden>
        </label>
      </div>
      <p class="capture-status small muted" hidden></p>
      <div class="capture-result">${captureContent(capture, r.provider)}</div>
    </div>`;
}

// Envia o print manual (Blob/File) para a consulta do histórico
async function uploadManualCapture(block, blob) {
  const status = block.querySelector(".capture-status");
  const provider = block.dataset.provider;
  status.hidden = false;
  status.textContent = "Salvando o print…";
  const form = new FormData();
  form.append("image", blob, blob.name || "print.png");
  try {
    const response = await fetch(`/api/capture/${block.dataset.entry}/manual?provider=${encodeURIComponent(provider)}`, {
      method: "POST",
      headers: { "X-Requested-With": "IOCCheck", Accept: "application/json" },
      body: form,
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Erro ${response.status}`);
    block.querySelector(".capture-result").innerHTML = captureContent(data, provider);
    status.textContent = "Print salvo com a marca d'água; ele fica no histórico desta consulta.";
    toast(`Print de ${provider} salvo.`, "success");
  } catch (err) {
    status.textContent = err.message;
    toast(err.message, "error");
  }
}

async function pasteCapture(block) {
  try {
    const items = await navigator.clipboard.read();
    for (const item of items) {
      const type = item.types.find((t) => t.startsWith("image/"));
      if (type) return uploadManualCapture(block, await item.getType(type));
    }
    toast("Nenhuma imagem na área de transferência. Tire o print com Win+Shift+S e tente de novo.", "error");
  } catch (_) {
    toast("O navegador não liberou a área de transferência: use \"Enviar imagem\" ou arraste o arquivo.", "error");
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-paste-capture]");
  if (button) pasteCapture(button.closest(".page-capture"));
});
document.addEventListener("change", (event) => {
  const input = event.target.closest("[data-upload-capture]");
  if (input && input.files[0]) {
    uploadManualCapture(input.closest(".page-capture"), input.files[0]);
    input.value = "";
  }
});
document.addEventListener("dragover", (event) => {
  const block = event.target.closest(".page-capture");
  if (block) {
    event.preventDefault();
    block.classList.add("drop-over");
  }
});
document.addEventListener("dragleave", (event) => {
  event.target.closest?.(".page-capture")?.classList.remove("drop-over");
});
document.addEventListener("drop", (event) => {
  const block = event.target.closest(".page-capture");
  if (!block) return;
  event.preventDefault();
  block.classList.remove("drop-over");
  const file = [...event.dataTransfer.files].find((f) => f.type.startsWith("image/"));
  if (file) uploadManualCapture(block, file);
  else toast("Solte um arquivo de imagem (PNG, JPG ou WebP).", "error");
});

async function capturePage(block) {
  const button = block.querySelector("[data-capture-page]");
  const status = block.querySelector(".capture-status");
  const provider = block.dataset.provider;
  button.disabled = true;
  status.hidden = false;
  status.textContent = `Abrindo a página de ${provider} numa janela do navegador… Se aparecer ` +
    `"Confirme que é humano", clique na caixa: o print é feito sozinho e a janela fecha.`;
  try {
    const capture = await API.post(`/api/capture/${block.dataset.entry}?provider=${encodeURIComponent(provider)}`);
    block.querySelector(".capture-result").innerHTML = captureContent(capture, provider);
    status.textContent = capture.needed_human
      ? "Print feito depois da verificação do site."
      : "Print feito.";
    button.textContent = "📸 Novo print automático";
    toast(`Print da página de ${provider} pronto. Use "Copiar print da página".`, "success");
  } catch (err) {
    // Sites que recusam navegador automatizado (ex.: verificação em loop): print manual
    status.textContent = `${err.message} Alternativa: clique em "🌐 Abrir no meu navegador", tire o print ` +
      `com Win+Shift+S e depois em "📋 Colar print".`;
    toast(err.message, "error");
  } finally {
    button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-capture-page]");
  if (button) capturePage(button.closest(".page-capture"));
});

// --- Barra lateral recolhível ----------------------------------------------

function renderCollapseButton() {
  const button = document.getElementById("collapse-btn");
  if (!button) return;
  const collapsed = document.documentElement.dataset.sidebar === "collapsed";
  const label = collapsed ? "Expandir o menu" : "Recolher o menu";
  button.setAttribute("aria-label", label);
  button.title = label;
}

document.getElementById("collapse-btn")?.addEventListener("click", () => {
  const root = document.documentElement;
  const collapsed = root.dataset.sidebar !== "collapsed";
  if (collapsed) root.dataset.sidebar = "collapsed";
  else delete root.dataset.sidebar;
  try {
    localStorage.setItem("ioc-sidebar", collapsed ? "collapsed" : "expanded");
  } catch (_) {
    // navegação privada: vale só para esta página
  }
  renderCollapseButton();
  window.dispatchEvent(new Event("resize")); // o hub do Painel redesenha as linhas
});
renderCollapseButton();

// --- Tema claro / escuro ---------------------------------------------------

function currentTheme() {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function renderThemeToggle() {
  const button = document.getElementById("theme-toggle");
  if (!button) return;
  const dark = currentTheme() === "dark";
  button.innerHTML = dark ? "☀️ <span>Claro</span>" : "🌙 <span>Escuro</span>";
  button.title = dark ? "Usar o tema claro" : "Usar o tema escuro";
}

// --- Encerrar (o servidor roda em segundo plano, sem janela do CMD) ----------

document.getElementById("shutdown-btn")?.addEventListener("click", async () => {
  if (!confirm("Encerrar o IOC Check? Para abrir de novo, use o iniciar.bat.")) return;
  try {
    const data = await API.post("/api/system/shutdown");
    document.querySelector("main.panel").innerHTML = `
      <section class="card"><h1>IOC Check encerrado</h1>
      <p class="muted">${escapeHtml(data.message)} Para abrir de novo, dê dois cliques no <code>iniciar.bat</code>.</p></section>`;
  } catch (err) {
    toast(err.message, "error");
  }
});

document.getElementById("theme-toggle")?.addEventListener("click", () => {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem("ioc-theme", next);
  } catch (_) {
    // navegação privada: o tema vale só para esta sessão
  }
  renderThemeToggle();
});
renderThemeToggle();
