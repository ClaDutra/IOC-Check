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

// Linhas da tabela "fonte por fonte", usada na verificação e nos detalhes do cache.
function providerRows(results) {
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
          <td class="nowrap"><strong>${escapeHtml(r.provider)}</strong></td>
          <td>${statusBadge(r.status)}</td>
          <td>${r.status === "ok" ? verdictBadge(r.verdict) : "—"}</td>
          <td>${escapeHtml(r.summary)}${escapeHtml(validity)}${link}${providerFlags(r)}</td>
        </tr>
        ${extras ? `<tr class="extras-row"><td colspan="4">${extras}</td></tr>` : ""}`;
    })
    .join("");
}

// Tudo abaixo vem de APIs externas, então todo texto passa por escapeHtml.

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
