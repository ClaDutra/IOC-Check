const filterForm = document.getElementById("filter-form");
const tbody = document.getElementById("history-body");
const exportBtn = document.getElementById("export-btn");

function row(log) {
  return `
    <tr>
      <td class="nowrap">${formatDate(log.queried_at)}</td>
      <td class="indicator">${escapeHtml(log.indicator)}</td>
      <td>${typeLabel(log.type)}</td>
      <td>${verdictBadge(log.verdict)}</td>
      <td>${log.score}</td>
      <td>${log.from_cache ? '<span class="badge info">Cache</span>' : '<span class="badge neutral">Nova</span>'}</td>
      <td class="nowrap" title="Data em que o resultado foi armazenado no cache">${formatDate(log.cache_stored_at)}</td>
    </tr>`;
}

async function load(page = 1) {
  const query = formQuery(filterForm);
  exportBtn.href = `/api/history/export${query ? `?${query}` : ""}`;
  try {
    const data = await API.get(`/api/history?${formQuery(filterForm, { page })}`);
    tbody.innerHTML = data.items.length ? data.items.map(row).join("") : emptyRow(7, "Nenhuma consulta encontrada.");
    renderPagination(document.getElementById("pagination"), data, load);
  } catch (err) {
    toast(err.message, "error");
  }
}

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  load(1);
});

document.getElementById("clear-history-btn").addEventListener("click", () =>
  clearData("/api/history", "Apagar todo o histórico de consultas?", () => load(1))
);

load();
