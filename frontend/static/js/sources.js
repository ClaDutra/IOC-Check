// Ícones das fontes de dados, desenhados para o IOC Check nas cores de cada ferramenta.
// Usados no hub do Painel, na tabela "fonte por fonte" e nas Configurações.

const SOURCES = {
  local: {
    name: "Base local", color: "#a78bfa",
    glyph: '<ellipse cx="12" cy="6" rx="7" ry="2.6"/><path d="M5 6v6c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6"/><path d="M5 12v6c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6v-6"/>',
  },
  virustotal: {
    name: "VirusTotal", color: "#4f7cff",
    glyph: '<rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="M8.5 7.5l5 4.5-5 4.5"/>',
  },
  abuseipdb: {
    name: "AbuseIPDB", color: "#ff4d5e",
    glyph: '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6L12 3z"/><path d="M12 8v5"/><path d="M12 16.2v.1"/>',
  },
  threatfox: {
    name: "ThreatFox", color: "#ff9a3d",
    glyph: '<path d="M4 4.5l4.5 3.5h7L20 4.5l-1 8.5-7 6.5-7-6.5z"/><path d="M9.3 12.3l.01 0M14.7 12.3l.01 0"/><path d="M10.8 15.4h2.4"/>',
  },
  hybrid_analysis: {
    name: "Hybrid Analysis", color: "#2ad4d0",
    glyph: '<path d="M12 2.8l7.8 4.6v9.2L12 21.2l-7.8-4.6V7.4z"/><circle cx="12" cy="12" r="2.2"/><path d="M12 9.8V6.2M13.9 13.1l3.1 1.8M10.1 13.1L7 14.9"/>',
  },
  urlscan: {
    name: "URLScan.io", color: "#38bdf8",
    glyph: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M4 10.5h13M10.5 4c1.8 1.9 2.6 4 2.6 6.5S12.3 15.1 10.5 17M10.5 4C8.7 5.9 7.9 8 7.9 10.5s.8 4.6 2.6 6.5"/><path d="M15.4 15.4L20 20"/>',
  },
  mxtoolbox: {
    name: "MxToolbox", color: "#ff6a3d",
    glyph: '<rect x="3" y="5.5" width="18" height="13" rx="2.5"/><path d="M3.8 7l8.2 6 8.2-6"/>',
  },
  ipinfo: {
    name: "IPinfo", color: "#5b8cff",
    glyph: '<path d="M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0113 0c0 5.4-6.5 11-6.5 11z"/><path d="M12 9.6v4"/><path d="M12 7.2v.1"/>',
  },
};

const SOURCE_BY_NAME = Object.fromEntries(Object.entries(SOURCES).map(([id, s]) => [s.name, id]));

// Aceita o id ("virustotal") ou o nome exibido ("VirusTotal")
function sourceInfo(key) {
  const id = SOURCES[key] ? key : SOURCE_BY_NAME[key];
  return id ? { id, ...SOURCES[id] } : null;
}

function sourceIcon(key, size = "") {
  const s = sourceInfo(key);
  if (!s) return "";
  return `<span class="src-icon ${size}" style="--brand:${s.color}" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
         stroke-linecap="round" stroke-linejoin="round">${s.glyph}</svg></span>`;
}
