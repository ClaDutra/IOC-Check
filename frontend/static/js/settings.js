// Botões da seção "Meus dados": cada um indica a rota e a pergunta de confirmação
document.querySelectorAll("[data-clear]").forEach((button) =>
  button.addEventListener("click", () => clearData(button.dataset.clear, button.dataset.question, loadCacheSummary))
);

// Resumo do cache (ele não tem mais tela própria: o histórico guarda os dados completos)
async function loadCacheSummary() {
  const box = document.getElementById("cache-stats");
  try {
    const s = await API.get("/api/cache/summary");
    box.innerHTML = `
      <div class="fact"><span>Válidos agora</span><strong>${s.valid}</strong></div>
      <div class="fact"><span>Expirados</span><strong>${s.expired}</strong></div>
      <div class="fact"><span>Reaproveitamentos</span><strong>${s.hits}</strong></div>
      <div class="fact"><span>Validade</span><strong>${s.ttl_hours} hora(s)</strong></div>
      <div class="fact"><span>Mais antigo</span><strong>${s.oldest_stored_at ? formatDate(s.oldest_stored_at) : "—"}</strong></div>`;
  } catch (err) {
    box.textContent = err.message;
  }
}

document.getElementById("purge-cache-btn").addEventListener("click", async () => {
  try {
    toast((await API.post("/api/cache/purge-expired")).message, "success");
    loadCacheSummary();
  } catch (err) {
    toast(err.message, "error");
  }
});
loadCacheSummary();

function providerStatus(p) {
  if (p.active && p.usage && p.usage.blocked_until) return '<span class="badge warn">Pausada</span>';
  if (p.active) return '<span class="badge good">Ativa</span>';
  if (!p.enabled) return '<span class="badge neutral">Desativada</span>';
  return '<span class="badge warn">Sem chave</span>';
}

function renderGeneral(general) {
  const form = document.getElementById("general-form");
  form.innerHTML = general
    .map((item) => `
      <label>${escapeHtml(item.label)}
        <input type="number" name="${item.key}" value="${item.value}" min="${item.min}" max="${item.max}" required>
        <span class="muted small">Origem: ${escapeHtml(item.source)} · entre ${item.min} e ${item.max}</span>
      </label>`)
    .join("") + `<div class="actions span-3"><button class="btn btn-primary" type="submit">Salvar</button></div>`;
}

function renderKeys(providers) {
  document.getElementById("keys-body").innerHTML = providers
    .map((p) => {
      const current = p.masked_key
        ? `<code>${escapeHtml(p.masked_key)}</code><br><span class="muted small">origem: ${escapeHtml(p.key_source)}</span>`
        : `<span class="badge ${p.key_required ? "warn" : "neutral"}">Não configurada</span>`;
      return `
        <tr data-id="${p.id}">
          <td class="nowrap">
            <span class="provider-name">${sourceIcon(p.id)}<strong>${escapeHtml(p.name)}</strong></span>
            <span class="muted small">${p.key_required ? "obrigatória" : "opcional"} ·
              <a href="${escapeHtml(p.signup_url)}" target="_blank" rel="noopener">obter chave</a></span>
          </td>
          <td class="key-cell">
            <div class="key-input">
              <input name="${p.id}_api_key" type="password" autocomplete="off" spellcheck="false"
                     placeholder="${p.masked_key ? "Digite para substituir" : "Cole a chave aqui"}">
              <button type="button" class="btn btn-sm btn-ghost" data-action="toggle" title="Mostrar/ocultar">Mostrar</button>
            </div>
            <p class="test-result small" hidden></p>
          </td>
          <td>${current}</td>
          <td>
            <div class="row-actions">
              <button type="button" class="btn btn-sm" data-action="test">Testar</button>
              ${p.key_source === "configurações" ? '<button type="button" class="btn btn-sm btn-danger" data-action="clear">Remover</button>' : ""}
            </div>
          </td>
        </tr>`;
    })
    .join("");
}

// Consumo da cota gratuita: chamadas de hoje, limites do plano e o que a API informou
function usageHtml(p) {
  const u = p.usage || {};
  const paused = u.blocked_until
    ? `<p class="flag bad">Pausada até ${escapeHtml(formatDate(u.blocked_until))} (limite gratuito atingido)</p>`
    : "";
  return `
    <div class="usage small">
      <span><strong>${u.calls_today ?? 0}</strong> consulta(s) hoje</span>
      ${u.free_limits ? `<span>Limite gratuito: ${escapeHtml(u.free_limits)}</span>` : ""}
      ${u.remote ? `<span>API informa: ${escapeHtml(u.remote)}</span>` : ""}
    </div>
    ${paused}
    <p class="small muted terms">${escapeHtml(p.terms || "")}</p>`;
}

function renderProviders(providers) {
  document.getElementById("providers").innerHTML = providers
    .map((p) => `
      <div class="card provider-card" data-id="${p.id}">
        <div class="card-head">
          <h2 class="provider-name">${sourceIcon(p.id, "lg")}${escapeHtml(p.name)}</h2>
          ${providerStatus(p)}
        </div>
        <p class="muted small">${escapeHtml(p.description)}</p>
        <p class="small">Tipos: ${p.types.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</p>
        <p class="small muted">Chave: ${p.has_key ? "configurada" : p.key_required ? "não configurada (cadastre em Chaves de API)" : "opcional"}</p>
        ${usageHtml(p)}
        <label class="checkbox">
          <input type="checkbox" data-action="enable" ${p.enabled ? "checked" : ""}> Usar esta fonte nas verificações
        </label>
      </div>`)
    .join("");
}

function render(data) {
  renderGeneral(data.general);
  renderKeys(data.providers);
  renderProviders(data.providers);
}

async function saveSettings(body) {
  try {
    const data = await API.put("/api/settings", body);
    render(data);
    loadCacheSummary();
    toast(data.message, "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function testProvider(row) {
  const output = row.querySelector(".test-result");
  const button = row.querySelector('[data-action="test"]');
  button.disabled = true;
  output.hidden = false;
  output.className = "test-result small muted";
  output.textContent = "Testando…";
  try {
    const data = await API.post(`/api/settings/providers/${row.dataset.id}/test`);
    output.className = `test-result small ${data.ok ? "ok" : "fail"}`;
    output.textContent = `${data.message} (teste com ${data.sample}: ${data.result.summary})`;
  } catch (err) {
    output.className = "test-result small fail";
    output.textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

async function loadSettings() {
  const keysForm = document.getElementById("keys-form");

  document.getElementById("general-form").addEventListener("submit", (event) => {
    event.preventDefault();
    saveSettings({ values: Object.fromEntries(new FormData(event.target)) });
  });

  // Envia só os campos preenchidos; os vazios mantêm a chave atual
  keysForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const values = Object.fromEntries(
      [...new FormData(keysForm)].filter(([, value]) => String(value).trim())
    );
    if (!Object.keys(values).length) {
      toast("Digite ao menos uma chave para salvar", "error");
      return;
    }
    saveSettings({ values });
  });

  keysForm.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const row = button.closest("tr");
    const action = button.dataset.action;

    if (action === "toggle") {
      const input = row.querySelector("input");
      input.type = input.type === "password" ? "text" : "password";
      button.textContent = input.type === "password" ? "Mostrar" : "Ocultar";
    } else if (action === "test") {
      testProvider(row);
    } else if (action === "clear") {
      if (confirm("Remover a chave salva? Se houver uma chave no arquivo .env, ela volta a ser usada.")) {
        saveSettings({ clear: [`${row.dataset.id}_api_key`] });
      }
    }
  });

  document.getElementById("providers").addEventListener("change", (event) => {
    if (event.target.dataset.action !== "enable") return;
    const id = event.target.closest(".provider-card").dataset.id;
    saveSettings({ values: { [`${id}_enabled`]: event.target.checked } });
  });

  render(await API.get("/api/settings"));
}

loadSettings().catch((err) => toast(err.message, "error"));
