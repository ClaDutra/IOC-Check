const VERDICT_ICON = { malicious: "!", suspicious: "?", clean: "✓", unknown: "–" };
const SOURCE_INITIALS = { virustotal: "VT", abuseipdb: "AB", threatfox: "TF", hybrid_analysis: "HA", urlscan: "US" };

function barList(container, entries, classFor) {
  if (!entries.length) {
    container.innerHTML = `<p class="muted small">Nenhuma consulta ainda.</p>`;
    return;
  }
  const total = entries.reduce((sum, e) => sum + e.value, 0);
  container.innerHTML = entries
    .map((e) => `
      <div class="bar-row">
        <span>${escapeHtml(e.label)}</span>
        <span class="count">${e.value}</span>
        <div class="bar-track"><div class="bar-fill ${classFor ? classFor(e.key) : ""}" style="width:${(e.value / total) * 100}%"></div></div>
      </div>`)
    .join("");
}

function columnChart(container, perDay) {
  const max = Math.max(1, ...perDay.map((d) => d.count));
  container.innerHTML = perDay
    .map((d, i) => {
      const [, month, day] = d.date.split("-");
      const isToday = i === perDay.length - 1;
      return `
        <div class="column ${isToday ? "today" : ""}" title="${d.count} consulta(s) em ${day}/${month}">
          <span class="col-value">${d.count || ""}</span>
          <div class="col-bar" style="height:${(d.count / max) * 110}px"></div>
          <span class="col-label">${isToday ? "Hoje" : day}</span>
        </div>`;
    })
    .join("");
}

function dayLabel(date) {
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  if (date.toDateString() === today.toDateString()) return "Hoje";
  if (date.toDateString() === yesterday.toDateString()) return "Ontem";
  const text = date.toLocaleDateString("pt-BR", { weekday: "long", day: "numeric", month: "long" });
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// Consultas recentes agrupadas por dia, no estilo de extrato
function renderActivity(container, recent) {
  if (!recent.length) {
    container.innerHTML = `
      <div class="day-group">
        <div class="day-head"><span>Atividade recente</span></div>
        <p class="empty">Nenhuma consulta ainda. <a href="/check">Faça sua primeira verificação</a>.</p>
      </div>`;
    return;
  }

  const groups = new Map();
  for (const item of recent) {
    const label = dayLabel(new Date(item.queried_at));
    if (!groups.has(label)) groups.set(label, []);
    groups.get(label).push(item);
  }

  container.innerHTML = [...groups]
    .map(([label, items]) => `
      <div class="day-group">
        <div class="day-head"><span>${escapeHtml(label)}</span><a class="dots" href="/history" title="Ver histórico">•••</a></div>
        <ul class="activity">
          ${items.map((r) => {
            const verdict = VERDICTS[r.verdict];
            const time = new Date(r.queried_at).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
            return `
              <li>
                <span class="activity-icon ${verdict.cls}" aria-hidden="true">${VERDICT_ICON[r.verdict]}</span>
                <div>
                  <div class="activity-title">${escapeHtml(r.indicator)}</div>
                  <div class="activity-sub">${time} • ${typeLabel(r.type)} • ${r.from_cache ? "do cache" : "consulta nova"}</div>
                </div>
                <div class="activity-score">${verdict.label}<span class="small muted">score ${r.score}</span></div>
              </li>`;
          }).join("")}
        </ul>
      </div>`)
    .join("");
}

function renderSources(container, providers) {
  const local = '<span class="source-dot local" title="Base local · ativa">BL</span>';
  container.innerHTML = local + providers
    .map((p) => `<span class="source-dot ${p.active ? "on" : ""}" title="${escapeHtml(p.name)} · ${escapeHtml(p.reason || "ativa")}">${SOURCE_INITIALS[p.id] || "?"}</span>`)
    .join("");
}

function renderTip(data) {
  // A dica muda conforme o estado: base vazia, IOCs vencidos ou fontes sem chave
  const title = document.getElementById("tip-title");
  const text = document.getElementById("tip-text");
  const btn = document.getElementById("tip-btn");
  const inactive = data.providers.filter((p) => !p.active).length;

  if (data.iocs.expired) {
    title.textContent = `${data.iocs.expired} IOC(s) expirado(s)`;
    text.textContent = "Indicadores vencidos não contam mais nas verificações. Renove ou remova-os da sua base.";
    btn.textContent = "Revisar base";
    btn.href = "/iocs";
  } else if (inactive) {
    title.textContent = "Ative mais fontes";
    text.textContent = `${inactive} fonte(s) externa(s) sem chave de API. Com mais fontes, os vereditos ficam mais confiáveis.`;
    btn.textContent = "Configurar chaves";
    btn.href = "/settings";
  }
}

async function loadDashboard() {
  const data = await API.get("/api/stats");
  const q = data.queries;

  const first = q.per_day[0].date.split("-").reverse().slice(0, 2).join("/");
  const last = q.per_day[q.per_day.length - 1].date.split("-").reverse().slice(0, 2).join("/");
  document.getElementById("period").textContent = `${first} – ${last}`;

  document.getElementById("st-queries").textContent = q.total;
  document.getElementById("st-hitrate").textContent = `${q.cache_hit_rate}%`;
  document.getElementById("st-hits").textContent = `${q.cache_hits} sem chamar APIs`;
  document.getElementById("st-iocs").textContent = data.iocs.total;
  document.getElementById("st-iocs-active").textContent = `${data.iocs.active} ativo(s) · ${data.iocs.expired} expirado(s)`;
  document.getElementById("st-cache").textContent = data.cache.valid;
  document.getElementById("st-cache-ttl").textContent = `validade de ${data.cache.ttl_hours}h`;

  renderSources(document.getElementById("source-dots"), data.providers);
  columnChart(document.getElementById("chart-days"), q.per_day);
  renderActivity(document.getElementById("activity"), q.recent);

  barList(
    document.getElementById("chart-verdicts"),
    Object.keys(VERDICTS)
      .filter((k) => q.by_verdict[k])
      .map((k) => ({ key: k, label: VERDICTS[k].label, value: q.by_verdict[k] })),
    (k) => VERDICTS[k].cls
  );
  barList(
    document.getElementById("chart-types"),
    Object.entries(q.by_type)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => ({ key: k, label: typeLabel(k), value: v }))
  );
  renderTip(data);
}

loadDashboard().catch((err) => toast(err.message, "error"));
