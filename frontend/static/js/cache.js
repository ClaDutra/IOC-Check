const filterForm = document.getElementById("filter-form");
const tbody = document.getElementById("cache-body");
const dialog = document.getElementById("detail-dialog");
let currentPage = 1;

function row(entry) {
  return `
    <tr>
      <td class="indicator">${escapeHtml(entry.indicator)}</td>
      <td>${typeLabel(entry.type)}</td>
      <td>${verdictBadge(entry.verdict)}</td>
      <td class="nowrap">${formatDate(entry.stored_at)}<br><span class="muted small">${relativeTime(entry.stored_at)}</span></td>
      <td class="nowrap">${formatDate(entry.expires_at)}<br><span class="muted small">${relativeTime(entry.expires_at)}</span></td>
      <td>${entry.expired ? '<span class="badge neutral">Expirado</span>' : '<span class="badge good">Válido</span>'}</td>
      <td>${entry.hits}</td>
      <td>
        <div class="row-actions">
          <button class="btn btn-sm" data-action="view" data-id="${entry.id}">Detalhes</button>
          <button class="btn btn-sm btn-danger" data-action="delete" data-id="${entry.id}">Remover</button>
        </div>
      </td>
    </tr>`;
}

function renderSummary(s) {
  document.getElementById("c-valid").textContent = s.valid;
  document.getElementById("c-expired").textContent = s.expired;
  document.getElementById("c-hits").textContent = s.hits;
  document.getElementById("c-ttl").textContent = `${s.ttl_hours}h`;
  document.getElementById("c-oldest").textContent = s.oldest_stored_at
    ? `entrada mais antiga: ${formatDate(s.oldest_stored_at)}`
    : "cache vazio";
}

async function load(page = 1) {
  currentPage = page;
  try {
    const data = await API.get(`/api/cache?${formQuery(filterForm, { page })}`);
    renderSummary(data.summary);
    tbody.innerHTML = data.items.length ? data.items.map(row).join("") : emptyRow(8, "Nenhuma entrada no cache.");
    renderPagination(document.getElementById("pagination"), data, load);
  } catch (err) {
    toast(err.message, "error");
  }
}

async function showDetails(id) {
  const entry = await API.get(`/api/cache/${id}`);
  document.getElementById("detail-title").textContent = entry.indicator;
  document.getElementById("detail-body").innerHTML = `
    <p class="result-meta">
      <span class="badge neutral">${typeLabel(entry.type)}</span>
      ${verdictBadge(entry.verdict)} <span>Score ${entry.score}/100</span>
    </p>
    <p class="cache-note">Armazenado em ${formatDate(entry.stored_at)} · expira em ${formatDate(entry.expires_at)} · reaproveitado ${entry.hits} vez(es)</p>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Fonte</th><th>Status</th><th>Veredito</th><th>Detalhe</th></tr></thead>
        <tbody>${providerRows(entry.results)}</tbody>
      </table>
    </div>`;
  dialog.showModal();
}

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  load(1);
});

document.getElementById("detail-close").addEventListener("click", () => dialog.close());

tbody.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  try {
    if (button.dataset.action === "view") {
      await showDetails(button.dataset.id);
    } else if (button.dataset.action === "delete") {
      await API.del(`/api/cache/${button.dataset.id}`);
      toast("Entrada removida do cache", "success");
      load(currentPage);
    }
  } catch (err) {
    toast(err.message, "error");
  }
});

document.getElementById("purge-btn").addEventListener("click", async () => {
  try {
    const data = await API.post("/api/cache/purge-expired");
    toast(data.message, "success");
    load(1);
  } catch (err) {
    toast(err.message, "error");
  }
});

document.getElementById("clear-btn").addEventListener("click", () =>
  clearData(
    "/api/cache",
    "Remover todas as entradas do cache? As próximas consultas chamarão as APIs novamente.",
    () => load(1)
  )
);

load();
