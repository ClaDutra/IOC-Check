const form = document.getElementById("check-form");
const resultsEl = document.getElementById("results");
const summaryEl = document.getElementById("check-summary");

const SAMPLES = [
  "198.51.100.23",
  "hxxp://phishing-login[.]example/conta/verificar",
  "44d88612fea8a8f36de82e1278abb02f",
  "8.8.8.8",
  "github.com",
  "isto-nao-e-um-ioc",
].join("\n");

document.getElementById("sample-btn").addEventListener("click", () => {
  form.indicators.value = SAMPLES;
});

function scoreBar(score, cls) {
  return `
    <div class="score" title="Score de risco">
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${score}%"></div></div>
      <strong>${score}</strong><span class="muted">/100</span>
    </div>`;
}

function cacheNote(r) {
  if (r.from_cache) {
    return `Resultado do <strong>cache</strong>, armazenado em ${formatDate(r.stored_at)} (${relativeTime(r.stored_at)}).
            Expira em ${formatDate(r.expires_at)}. Reaproveitado ${r.hits} vez(es).`;
  }
  return `Consulta nova, armazenada no cache em ${formatDate(r.stored_at)}. Válida até ${formatDate(r.expires_at)}.
          Os dados e os prints ficam guardados no <a href="/history">Histórico</a>.`;
}

// Fontes que deram alerta, mostradas na linha do IOC quando ele está recolhido
function alertSources(r) {
  const alerts = r.results.filter((p) => p.status === "ok" && ["malicious", "suspicious"].includes(p.verdict));
  if (!alerts.length) return '<span class="muted small">nenhuma fonte com alerta</span>';
  return `<span class="alert-sources">${alerts.map((p) =>
    `<span class="alert-source ${VERDICTS[p.verdict].cls}" title="${escapeHtml(p.provider)}: ${escapeHtml(VERDICTS[p.verdict].label)}">${sourceIcon(p.provider)}</span>`).join("")}
    <span class="muted small">${alerts.length} fonte(s) com alerta</span></span>`;
}

const TOGGLE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>';

function renderResult(r, collapsed = false) {
  if (!r.valid) {
    return `
      <article class="card result">
        <div class="result-head">
          <div><div class="result-value">${escapeHtml(r.input)}</div>
          <div class="result-meta"><span class="badge neutral">Inválido</span> ${escapeHtml(r.error)}</div></div>
        </div>
      </article>`;
  }

  const verdict = VERDICTS[r.verdict];
  const local = r.results.find((p) => p.provider === "Base local");
  const canAdd = local && local.status !== "ok";

  return `
    <article class="card result ${verdict.cls}${collapsed ? " collapsed" : ""}">
      <div class="result-head" data-toggle-result>
        <button type="button" class="result-toggle" aria-expanded="${!collapsed}"
                title="${collapsed ? "Expandir" : "Recolher"} este IOC">${TOGGLE_ICON}</button>
        <div class="result-title">
          <div class="result-value">${escapeHtml(r.indicator)}</div>
          <div class="result-meta">
            <span class="badge neutral">${typeLabel(r.type)}</span>
            ${verdictBadge(r.verdict)}
            ${r.from_cache ? '<span class="badge info">Cache</span>' : '<span class="badge neutral">Consulta nova</span>'}
            ${r.input !== r.indicator ? `<span>entrada original: <code>${escapeHtml(r.input)}</code></span>` : ""}
          </div>
          <div class="result-collapsed-info">${alertSources(r)}</div>
        </div>
        <div class="result-side">
          ${scoreBar(r.score, verdict.cls)}
          ${r.history_id ? evidenceActions(evidenceUrl(r.history_id), "evidência completa", true) : ""}
        </div>
      </div>
      <div class="result-body">
      <div class="table-wrap provider-table">
        <table class="table">
          <thead><tr><th>Fonte</th><th>Status</th><th>Veredito</th><th>Detalhe</th></tr></thead>
          <tbody>${providerRows(r.results, r.history_id, r.captures || {})}</tbody>
        </table>
      </div>
      <p class="cache-note">${cacheNote(r)}</p>
      ${canAdd ? `
        <form class="add-form" data-value="${escapeHtml(r.indicator)}">
          <select name="severity">
            <option value="critical">Crítica</option>
            <option value="high" selected>Alta</option>
            <option value="medium">Média</option>
            <option value="low">Baixa</option>
          </select>
          <select name="expiration" title="Validade do IOC">${expirationOptions({ custom: false })}</select>
          <input name="description" placeholder="Descrição (opcional)">
          <button class="btn btn-sm" type="submit">Adicionar à base local</button>
        </form>` : ""}
      </div>
    </article>`;
}

// --- Recolher / expandir IOCs --------------------------------------------------

function setCollapsed(article, collapsed) {
  article.classList.toggle("collapsed", collapsed);
  const button = article.querySelector(".result-toggle");
  if (button) {
    button.setAttribute("aria-expanded", String(!collapsed));
    button.title = `${collapsed ? "Expandir" : "Recolher"} este IOC`;
  }
}

resultsEl.addEventListener("click", (event) => {
  const head = event.target.closest("[data-toggle-result]");
  // cliques em botões, links e formulários do cabeçalho (ex.: copiar evidência) não recolhem
  if (!head || (event.target.closest("a, button, input, select, label") && !event.target.closest(".result-toggle"))) return;
  const article = head.closest(".result");
  setCollapsed(article, !article.classList.contains("collapsed"));
});

function renderToolbar(count) {
  document.getElementById("results-toolbar").hidden = count < 1;
}

document.getElementById("collapse-all-btn").addEventListener("click", () =>
  resultsEl.querySelectorAll(".result").forEach((a) => setCollapsed(a, true)));
document.getElementById("expand-all-btn").addEventListener("click", () =>
  resultsEl.querySelectorAll(".result").forEach((a) => setCollapsed(a, false)));

resultsEl.addEventListener("submit", async (event) => {
  const addForm = event.target.closest(".add-form");
  if (!addForm) return;
  event.preventDefault();
  try {
    const payload = {
      value: addForm.dataset.value,
      severity: addForm.severity.value,
      description: addForm.description.value,
      source: "Verificação manual",
    };
    const expiresAt = expirationValue(addForm.expiration.value);
    if (expiresAt !== undefined) payload.expires_at = expiresAt;
    await API.post("/api/iocs", payload);
    addForm.outerHTML = `<p class="cache-note">Adicionado à base local. O cache deste indicador foi invalidado — verifique novamente para ver o novo veredito.</p>`;
    toast("Indicador adicionado à base local", "success");
  } catch (err) {
    toast(err.message, "error");
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.getElementById("check-btn");
  button.disabled = true;
  button.textContent = "Verificando…";
  summaryEl.textContent = "";

  try {
    const data = await API.post("/api/check", {
      indicators: form.indicators.value,
      force_refresh: form.force_refresh.checked,
    });
    const s = data.summary;
    summaryEl.textContent =
      `${s.total} indicador(es) processado(s) · ${s.from_cache} do cache · ${s.invalid} inválido(s)`;
    // Todos os IOCs chegam recolhidos (veredito, score e fontes com alerta); clique para expandir
    resultsEl.innerHTML = data.results.map((r) => renderResult(r, r.valid)).join("");
    renderToolbar(data.results.length);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "Verificar";
  }
});

// /check?q=<indicador> preenche e verifica automaticamente
// (usado pelos links "verificar" dos hashes de arquivos baixados)
const initialQuery = new URLSearchParams(window.location.search).get("q");
if (initialQuery) {
  form.indicators.value = initialQuery;
  form.requestSubmit();
}
