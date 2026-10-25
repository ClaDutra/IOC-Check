const filterForm = document.getElementById("filter-form");
const tbody = document.getElementById("logs-body");
const sourceFilter = document.getElementById("source-filter");
const CATEGORY = { acao: "Ação", api: "API", sistema: "Sistema" };
const LEVEL = { info: ["Info", "neutral"], aviso: ["Aviso", "warn"], erro: ["Erro", "bad"] };
let currentPage = 1;
let itemsById = {};

function sourceCell(source) {
  const info = sourceInfo(source);
  return `<span class="log-source">${info ? sourceIcon(source) : ""}${escapeHtml(info ? info.name : source || "—")}</span>`;
}

function row(log) {
  const [levelLabel, levelCls] = LEVEL[log.level] || [log.level, "neutral"];
  const time = new Date(log.created_at).toLocaleString("pt-BR", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  return `
    <tr class="log-row" data-id="${log.id}" title="${log.details ? "Clique para ver os detalhes" : ""}">
      <td class="nowrap">${time}</td>
      <td><span class="badge cat-${escapeHtml(log.category)}">${CATEGORY[log.category] || escapeHtml(log.category)}</span></td>
      <td>${sourceCell(log.source)}</td>
      <td class="log-message">${escapeHtml(log.message)}</td>
      <td><span class="badge ${levelCls}">${levelLabel}${log.status_code ? ` · ${log.status_code}` : ""}</span></td>
      <td class="nowrap muted">${log.duration_ms != null ? `${log.duration_ms} ms` : "—"}</td>
    </tr>`;
}

function renderSummary(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  document.getElementById("log-summary").innerHTML = [
    ["Registros", total], ["Ações", counts.acao || 0], ["Chamadas às APIs", counts.api || 0], ["Sistema", counts.sistema || 0],
  ].map(([label, value]) => `<span class="pill">${label}<strong>${value}</strong></span>`).join("");
}

function renderSources(sources) {
  const current = sourceFilter.value;
  sourceFilter.innerHTML = '<option value="">Todas as origens</option>' + sources
    .map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(sourceInfo(s) ? sourceInfo(s).name : s)}</option>`)
    .join("");
  sourceFilter.value = sources.includes(current) ? current : "";
}

async function load(page = 1) {
  currentPage = page;
  const query = formQuery(filterForm, { page, per_page: 50 });
  document.getElementById("export-btn").href = `/api/logs/export?${formQuery(filterForm)}`;
  try {
    const data = await API.get(`/api/logs?${query}`);
    itemsById = Object.fromEntries(data.items.map((i) => [i.id, i]));
    tbody.innerHTML = data.items.length ? data.items.map(row).join("") : emptyRow(6, "Nenhum registro encontrado.");
    renderSummary(data.counts);
    renderSources(data.sources);
    renderPagination(document.getElementById("pagination"), data, load);
  } catch (err) {
    toast(err.message, "error");
  }
}

// Clique na linha: mostra a requisição e a resposta completas (JSON formatado)
tbody.addEventListener("click", (event) => {
  const tr = event.target.closest("tr.log-row");
  if (!tr) return;
  const open = tr.nextElementSibling && tr.nextElementSibling.classList.contains("log-detail");
  if (open) {
    tr.nextElementSibling.remove();
    return;
  }
  const log = itemsById[tr.dataset.id];
  if (!log || !log.details) return;
  let details = log.details;
  // o corpo da resposta costuma ser JSON: formata para ficar legível
  const content = details.resposta && details.resposta.conteudo;
  if (content) {
    try {
      details = { ...details, resposta: { ...details.resposta, conteudo: JSON.parse(content) } };
    } catch (_) {
      // texto truncado ou não-JSON: mostra como veio
    }
  }
  tr.insertAdjacentHTML("afterend", `
    <tr class="log-detail"><td colspan="6">
      <pre>${escapeHtml(JSON.stringify(details, null, 2))}</pre>
    </td></tr>`);
});

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  load(1);
});
sourceFilter.addEventListener("change", () => load(1));
document.getElementById("refresh-btn").addEventListener("click", () => load(currentPage));
document.getElementById("clear-btn").addEventListener("click", () =>
  clearData("/api/logs", "Apagar todos os registros de log?", () => load(1))
);

load();
