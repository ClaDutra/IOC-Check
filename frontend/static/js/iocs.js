const filterForm = document.getElementById("filter-form");
const formCard = document.getElementById("form-card");
const iocForm = document.getElementById("ioc-form");
const formError = document.getElementById("form-error");
const tbody = document.getElementById("iocs-body");
const dateLabel = document.getElementById("expiration-date-label");
const purgeBtn = document.getElementById("purge-expired-btn");
let currentPage = 1;
let itemsById = {};
let defaultExpirationDays = 90;

function openForm(ioc) {
  iocForm.reset();
  formError.textContent = "";
  document.getElementById("form-title").textContent = ioc ? "Editar IOC" : "Novo IOC";
  iocForm.ioc_id.value = ioc ? ioc.id : "";
  iocForm.expiration.innerHTML = ioc
    ? expirationOptions({ current: ioc.expires_at })
    : expirationOptions({ defaultDays: defaultExpirationDays });
  dateLabel.hidden = true;
  if (ioc) {
    iocForm.value.value = ioc.value;
    iocForm.severity.value = ioc.severity;
    iocForm.source.value = ioc.source;
    iocForm.tags.value = ioc.tags.join(", ");
    iocForm.description.value = ioc.description;
    iocForm.active.checked = ioc.active;
  }
  formCard.hidden = false;
  formCard.scrollIntoView({ behavior: "smooth" });
  iocForm.value.focus();
}

function statusBadgeFor(ioc) {
  if (!ioc.active) return '<span class="badge neutral">Desativado</span>';
  if (ioc.expired) return '<span class="badge bad">Expirado</span>';
  return '<span class="badge good">Ativo</span>';
}

function row(ioc) {
  return `
    <tr>
      <td class="indicator" title="${escapeHtml(ioc.description)}"><a href="#" data-action="details" data-id="${ioc.id}">${escapeHtml(ioc.value)}</a></td>
      <td>${typeLabel(ioc.type)}</td>
      <td>${severityBadge(ioc.severity)}</td>
      <td>${ioc.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("") || '<span class="muted">—</span>'}</td>
      <td>${statusBadgeFor(ioc)}</td>
      <td class="nowrap">${expirationCell(ioc)}</td>
      <td class="nowrap">${formatDate(ioc.created_at)}</td>
      <td>
        <div class="row-actions">
          ${ioc.expired ? `<button class="btn btn-sm" data-action="renew" data-id="${ioc.id}" title="Renovar por ${defaultExpirationDays || 90} dias">Renovar</button>` : ""}
          <button class="btn btn-sm btn-primary" data-action="details" data-id="${ioc.id}">Detalhes</button>
          <button class="btn btn-sm" data-action="edit" data-id="${ioc.id}">Editar</button>
          <button class="btn btn-sm btn-danger" data-action="delete" data-id="${ioc.id}">Excluir</button>
        </div>
      </td>
    </tr>`;
}

async function load(page = 1) {
  currentPage = page;
  try {
    const data = await API.get(`/api/iocs?${formQuery(filterForm, { page })}`);
    defaultExpirationDays = data.default_expiration_days;
    itemsById = Object.fromEntries(data.items.map((i) => [i.id, i]));
    tbody.innerHTML = data.items.length ? data.items.map(row).join("") : emptyRow(8, "Nenhum IOC encontrado.");
    purgeBtn.textContent = `Remover expirados (${data.expired_total})`;
    purgeBtn.disabled = data.expired_total === 0;
    renderPagination(document.getElementById("pagination"), data, load);
  } catch (err) {
    toast(err.message, "error");
  }
}

// --- Detalhes do IOC: dados da base + última verificação completa (com prints) ---

const detailDialog = document.getElementById("detail-dialog");

function detailFact(label, value) {
  return `<div class="fact"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`;
}

async function showDetails(id) {
  const data = await API.get(`/api/iocs/${id}/details`);
  const ioc = data.ioc;
  const latest = data.latest;
  document.getElementById("detail-title").textContent = ioc.value;

  const facts = [
    detailFact("Tipo", typeLabel(ioc.type)),
    detailFact("Severidade", severityBadge(ioc.severity)),
    detailFact("Status", statusBadgeFor(ioc)),
    detailFact("Validade", ioc.expires_at ? `${formatDay(ioc.expires_at)} (${relativeTime(ioc.expires_at)})` : "Nunca expira"),
    detailFact("Fonte", escapeHtml(ioc.source || "—")),
    detailFact("Tags", ioc.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("") || "—"),
    detailFact("Cadastrado em", formatDate(ioc.created_at)),
    detailFact("Atualizado em", formatDate(ioc.updated_at)),
  ].join("");

  const latestHtml = latest ? `
    <section class="detail-section">
      <div class="card-head">
        <h3>Última verificação · ${formatDate(latest.queried_at)}</h3>
        <span>${verdictBadge(latest.verdict)} <span class="muted small">score ${latest.score}/100</span></span>
      </div>
      ${evidenceActions(evidenceUrl(latest.id), "evidência completa", true)}
      <div class="table-wrap provider-table">
        <table class="table">
          <thead><tr><th>Fonte</th><th>Status</th><th>Veredito</th><th>Detalhe</th></tr></thead>
          <tbody>${providerRows(latest.results, latest.id, latest.captures || {})}</tbody>
        </table>
      </div>
    </section>` : `
    <section class="detail-section">
      <p class="muted">Este IOC ainda não foi verificado nas fontes. Clique em <strong>Verificar agora</strong>
        para consultar todas as ferramentas e guardar o resultado.</p>
    </section>`;

  const queries = data.queries.length ? `
    <section class="detail-section">
      <h3>Consultas deste IOC (${data.total_queries})</h3>
      <ul class="ioc-queries">${data.queries.map((q) => `
        <li><span>${formatDate(q.queried_at)} · ${q.from_cache ? "do cache" : "consulta nova"}</span>
            <span>${verdictBadge(q.verdict)} <span class="muted small">score ${q.score}</span></span></li>`).join("")}
      </ul>
    </section>` : "";

  document.getElementById("detail-body").innerHTML = `
    <div class="ioc-detail-head">
      <a class="btn btn-primary btn-sm" href="/check?q=${encodeURIComponent(ioc.value)}">🔎 Verificar agora</a>
      <button type="button" class="btn btn-sm" id="detail-edit">Editar</button>
    </div>
    ${ioc.description ? `<p>${escapeHtml(ioc.description)}</p>` : ""}
    <div class="facts">${facts}</div>
    ${latestHtml}
    ${queries}`;
  document.getElementById("detail-edit").addEventListener("click", () => {
    detailDialog.close();
    openForm(ioc);
  });
  detailDialog.showModal();
}

document.getElementById("detail-close").addEventListener("click", () => detailDialog.close());

document.getElementById("new-btn").addEventListener("click", () => openForm(null));
document.getElementById("cancel-btn").addEventListener("click", () => (formCard.hidden = true));

iocForm.expiration.addEventListener("change", () => {
  dateLabel.hidden = iocForm.expiration.value !== "custom";
});

document.getElementById("clear-base-btn").addEventListener("click", () =>
  clearData(
    "/api/iocs",
    "Apagar TODOS os IOCs da sua base? Esta ação não pode ser desfeita.",
    () => load(1)
  )
);

purgeBtn.addEventListener("click", async () => {
  if (!confirm("Remover da base todos os IOCs com prazo vencido?")) return;
  try {
    const data = await API.post("/api/iocs/purge-expired");
    toast(data.message, "success");
    load(1);
  } catch (err) {
    toast(err.message, "error");
  }
});

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  load(1);
});

iocForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.textContent = "";
  const id = iocForm.ioc_id.value;
  try {
    const payload = {
      value: iocForm.value.value,
      severity: iocForm.severity.value,
      source: iocForm.source.value,
      tags: iocForm.tags.value,
      description: iocForm.description.value,
      active: iocForm.active.checked,
    };
    const expiresAt = expirationValue(iocForm.expiration.value, iocForm.expiration_date.value);
    if (expiresAt !== undefined) payload.expires_at = expiresAt;

    if (id) {
      await API.put(`/api/iocs/${id}`, payload);
      toast("IOC atualizado", "success");
    } else {
      await API.post("/api/iocs", payload);
      toast("IOC cadastrado", "success");
    }
    formCard.hidden = true;
    load(id ? currentPage : 1);
  } catch (err) {
    formError.textContent = err.message;
  }
});

tbody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  event.preventDefault();
  const ioc = itemsById[button.dataset.id];
  const action = button.dataset.action;

  try {
    if (action === "details") {
      await showDetails(ioc.id);
    } else if (action === "edit") {
      openForm(ioc);
    } else if (action === "renew") {
      await API.put(`/api/iocs/${ioc.id}`, { expires_at: expirationValue(String(defaultExpirationDays || 90)) });
      toast("Validade renovada", "success");
      load(currentPage);
    } else if (action === "delete") {
      if (!confirm(`Excluir o IOC ${ioc.value}?`)) return;
      await API.del(`/api/iocs/${ioc.id}`);
      toast("IOC excluído", "success");
      load(currentPage);
    }
  } catch (err) {
    toast(err.message, "error");
  }
});

load();
