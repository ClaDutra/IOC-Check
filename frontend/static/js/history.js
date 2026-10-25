const filterForm = document.getElementById("filter-form");
const tbody = document.getElementById("history-body");
const detailDialog = document.getElementById("detail-dialog");
const exportDialog = document.getElementById("export-dialog");
const exportForm = document.getElementById("export-form");
const selectPage = document.getElementById("select-page");
const selected = new Set(); // ids escolhidos, mantidos ao trocar de página
let currentPage = 1;
let pageIds = [];

function row(log) {
  return `
    <tr class="${selected.has(log.id) ? "selected" : ""}">
      <td class="check-col"><input type="checkbox" data-select="${log.id}" ${selected.has(log.id) ? "checked" : ""}
          aria-label="Selecionar ${escapeHtml(log.indicator)}"></td>
      <td class="nowrap">${formatDate(log.queried_at)}</td>
      <td class="indicator">${escapeHtml(log.indicator)}</td>
      <td>${typeLabel(log.type)}</td>
      <td>${verdictBadge(log.verdict)}</td>
      <td>${log.score}</td>
      <td>${log.from_cache ? '<span class="badge info">Cache</span>' : '<span class="badge neutral">Nova</span>'}</td>
      <td class="nowrap" title="Data em que o resultado foi obtido das fontes">${formatDate(log.cache_stored_at)}</td>
      <td>
        <div class="row-actions">
          <button class="btn btn-sm" data-action="view" data-id="${log.id}" ${log.has_details ? "" : 'disabled title="Consulta anterior à gravação dos dados completos"'}>Detalhes</button>
          <button class="btn btn-sm btn-ghost" data-action="delete" data-id="${log.id}" title="Excluir do histórico">✕</button>
        </div>
      </td>
    </tr>`;
}

function renderSelection() {
  const bar = document.getElementById("selection-bar");
  bar.hidden = selected.size === 0;
  document.getElementById("selection-count").textContent = `${selected.size} consulta(s) selecionada(s)`;
  const onPage = pageIds.filter((id) => selected.has(id)).length;
  selectPage.checked = pageIds.length > 0 && onPage === pageIds.length;
  selectPage.indeterminate = onPage > 0 && onPage < pageIds.length;
  tbody.querySelectorAll("input[data-select]").forEach((box) => {
    box.checked = selected.has(Number(box.dataset.select));
    box.closest("tr").classList.toggle("selected", box.checked);
  });
}

async function load(page = 1) {
  currentPage = page;
  try {
    const data = await API.get(`/api/history?${formQuery(filterForm, { page })}`);
    pageIds = data.items.map((log) => log.id);
    tbody.innerHTML = data.items.length ? data.items.map(row).join("") : emptyRow(9, "Nenhuma consulta encontrada.");
    renderPagination(document.getElementById("pagination"), data, load);
    renderSelection();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function showDetails(id) {
  const log = await API.get(`/api/history/${id}`);
  document.getElementById("detail-title").textContent = log.indicator;
  document.getElementById("detail-body").innerHTML = `
    <p class="result-meta">
      <span class="badge neutral">${typeLabel(log.type)}</span>
      ${verdictBadge(log.verdict)} <span>Score ${log.score}/100</span>
      ${log.from_cache ? '<span class="badge info">Cache</span>' : '<span class="badge neutral">Consulta nova</span>'}
    </p>
    <p class="cache-note">Consultado em ${formatDate(log.queried_at)} · dados obtidos das fontes em ${formatDate(log.cache_stored_at)}</p>
    ${evidenceActions(evidenceUrl(log.id), "evidência completa", true)}
    <div class="table-wrap provider-table">
      <table class="table">
        <thead><tr><th>Fonte</th><th>Status</th><th>Veredito</th><th>Detalhe</th></tr></thead>
        <tbody>${providerRows(log.results, log.id, log.captures || {})}</tbody>
      </table>
    </div>`;
  detailDialog.showModal();
}

function openExport(scope) {
  const selectedOption = exportForm.querySelector('input[name="scope"][value="selected"]');
  selectedOption.disabled = selected.size === 0;
  document.getElementById("scope-selected-label").textContent = selected.size
    ? `Somente as selecionadas (${selected.size})`
    : "Somente as selecionadas (marque as consultas na tabela)";
  exportForm.querySelector(`input[name="scope"][value="${selected.size && scope !== "filter" ? "selected" : "filter"}"]`).checked = true;
  exportDialog.showModal();
}

exportForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const include = [...exportForm.querySelectorAll('input[name="include"]:checked')].map((box) => box.value);
  if (!include.length) {
    toast("Escolha ao menos um item para exportar", "error");
    return;
  }
  const scope = exportForm.querySelector('input[name="scope"]:checked').value;
  const params = new URLSearchParams(formQuery(filterForm));
  if (scope === "selected") {
    params.set("ids", [...selected].join(","));
    ["q", "verdict", "type", "source"].forEach((key) => params.delete(key)); // a seleção vale por si
  }
  params.set("include", include.join(","));
  window.location.href = `/api/history/export?${params}`;
  exportDialog.close();
  toast(include.some((p) => p === "evidence" || p === "pages")
    ? "Gerando a exportação com as imagens… o download começa em instantes."
    : "Exportação iniciada.", "success");
});

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  load(1);
});

tbody.addEventListener("change", (event) => {
  const box = event.target.closest("input[data-select]");
  if (!box) return;
  const id = Number(box.dataset.select);
  if (box.checked) selected.add(id);
  else selected.delete(id);
  renderSelection();
});

selectPage.addEventListener("change", () => {
  pageIds.forEach((id) => (selectPage.checked ? selected.add(id) : selected.delete(id)));
  renderSelection();
});

tbody.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const id = Number(button.dataset.id);
  try {
    if (button.dataset.action === "view") {
      await showDetails(id);
    } else if (button.dataset.action === "delete") {
      if (!confirm("Excluir esta consulta do histórico, com os dados e os prints guardados?")) return;
      toast((await API.del(`/api/history/${id}`)).message, "success");
      selected.delete(id);
      load(currentPage);
    }
  } catch (err) {
    toast(err.message, "error");
  }
});

document.getElementById("detail-close").addEventListener("click", () => detailDialog.close());
document.getElementById("export-close").addEventListener("click", () => exportDialog.close());
document.getElementById("export-btn").addEventListener("click", () => openExport());
document.getElementById("export-selected-btn").addEventListener("click", () => openExport("selected"));
document.getElementById("clear-selection-btn").addEventListener("click", () => {
  selected.clear();
  renderSelection();
});

document.getElementById("delete-selected-btn").addEventListener("click", async () => {
  if (!confirm(`Excluir ${selected.size} consulta(s) do histórico, com os dados e os prints guardados?`)) return;
  try {
    const data = await API.post("/api/history/delete", { ids: [...selected] });
    toast(data.message, "success");
    selected.clear();
    load(1);
  } catch (err) {
    toast(err.message, "error");
  }
});

document.getElementById("clear-history-btn").addEventListener("click", () =>
  clearData("/api/history", "Apagar todo o histórico de consultas, com os dados e os prints guardados?", () => {
    selected.clear();
    load(1);
  })
);

load();
