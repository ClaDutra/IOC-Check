const VERDICT_ICON = { malicious: "!", suspicious: "?", clean: "✓", unknown: "–" };

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

// Hub "Fontes conectadas": base local + ferramentas ligadas ao IOC Check
function hubCard(item) {
  const paused = item.usage && item.usage.blocked_until;
  const state = paused ? "paused" : item.active ? "on" : "off";
  let sub;
  if (item.id === "local") sub = item.sub;
  else if (paused) sub = "Pausada · limite gratuito";
  else if (item.active) sub = `Ativa · ${item.usage ? item.usage.calls_today : 0} consulta(s) hoje`;
  else sub = item.reason || "Inativa";
  return `
    <a class="hub-card ${state}" href="${item.href}" title="${escapeHtml(item.name)}: ${escapeHtml(sub)}">
      ${sourceIcon(item.id, "lg")}
      <span class="hub-text"><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(sub)}</span></span>
      <span class="hub-action" aria-hidden="true">${item.active ? "↗" : "+"}</span>
    </a>`;
}

function renderHub(data) {
  const items = [
    { id: "local", name: "Base local", active: true, href: "/iocs",
      sub: `${data.iocs.active} IOC(s) ativo(s)` },
    ...data.providers.map((p) => ({ ...p, href: "/settings" })),
  ];
  const half = Math.ceil(items.length / 2);
  document.getElementById("hub-left").innerHTML = items.slice(0, half).map(hubCard).join("");
  document.getElementById("hub-right").innerHTML = items.slice(half).map(hubCard).join("");
  const active = data.providers.filter((p) => p.active).length;
  document.getElementById("hub-count").textContent = `${active} de ${data.providers.length} ferramentas ativas`;
  drawHubLines();
}

// Linhas que ligam cada cartão ao escudo central. São calculadas com a posição real
// dos elementos na tela, então ficam alinhadas em qualquer largura de janela.
function drawHubLines() {
  const hub = document.getElementById("hub");
  const logo = hub && hub.querySelector(".core-logo");
  if (!logo) return;
  let svg = hub.querySelector(".hub-lines");
  if (!svg) {
    svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("hub-lines");
    svg.setAttribute("aria-hidden", "true");
    hub.prepend(svg);
  }
  if (getComputedStyle(svg).display === "none") return; // telas estreitas: hub em pilha, sem linhas

  const box = hub.getBoundingClientRect();
  const orb = logo.getBoundingClientRect();
  const cx = orb.left + orb.width / 2 - box.left;
  const cy = orb.top + orb.height / 2 - box.top;
  const r = orb.width / 2 + 6;
  svg.setAttribute("viewBox", `0 0 ${box.width} ${box.height}`);

  const parts = [];
  hub.querySelectorAll(".hub-card").forEach((card) => {
    const rect = card.getBoundingClientRect();
    const left = rect.right - box.left < cx;
    const x1 = left ? rect.right - box.left : rect.left - box.left;
    const y1 = rect.top + rect.height / 2 - box.top;
    // chegam ao escudo levemente espalhadas, como raios
    const y2 = cy + (y1 - cy) * 0.32;
    const x2 = cx + (left ? -1 : 1) * Math.sqrt(Math.max(r * r - (y2 - cy) ** 2, 0));
    const bend = (x2 - x1) * 0.55;
    const state = card.classList.contains("paused") ? "paused" : card.classList.contains("on") ? "on" : "";
    parts.push(`<path class="${state}" d="M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}"/>`,
               `<circle cx="${x1}" cy="${y1}" r="2.5"/>`);
  });
  svg.innerHTML = parts.join("");
}

// Redesenha sempre que o hub muda de tamanho (janela, zoom, fontes carregando...)
let hubFrame;
if (window.ResizeObserver && document.getElementById("hub")) {
  new ResizeObserver(() => {
    cancelAnimationFrame(hubFrame);
    hubFrame = requestAnimationFrame(drawHubLines);
  }).observe(document.getElementById("hub"));
} else {
  window.addEventListener("resize", drawHubLines);
}
if (document.fonts) document.fonts.ready.then(drawHubLines); // fontes mudam a altura dos cartões

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


  document.getElementById("st-queries").textContent = q.total;
  document.getElementById("st-hitrate").textContent = `${q.cache_hit_rate}%`;
  document.getElementById("st-hits").textContent = `${q.cache_hits} sem chamar APIs`;
  document.getElementById("st-iocs").textContent = data.iocs.total;
  document.getElementById("st-iocs-active").textContent = `${data.iocs.active} ativo(s) · ${data.iocs.expired} expirado(s)`;
  document.getElementById("st-cache").textContent = data.cache.valid;
  document.getElementById("st-cache-ttl").textContent = `validade de ${data.cache.ttl_hours}h`;

  renderHub(data);
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
