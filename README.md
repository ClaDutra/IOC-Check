<div align="center">

# 🛡️ IOC Check

**Verificador pessoal de Indicadores de Comprometimento (IOCs)**

Consulte IPs, domínios, URLs, e-mails e hashes em várias fontes de inteligência de ameaças
de uma só vez, monte sua própria base de indicadores e economize a cota das APIs com cache.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-SQLAlchemy-003B57?logo=sqlite&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-Fetch%20API-F7DF1E?logo=javascript&logoColor=black)
![Testes](https://img.shields.io/badge/testes-pytest-60519b)

</div>

---

## Sumário

- [Sobre o projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Tecnologias](#tecnologias)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Como executar](#como-executar)
- [Configuração](#configuração)
- [Fontes de dados](#fontes-de-dados)
- [Como funciona](#como-funciona)
- [API REST](#api-rest)
- [Testes](#testes)
- [Segurança](#segurança)

---

## Sobre o projeto

Profissionais de TI, analistas de segurança, estudantes e pequenas empresas sem um
SOC estruturado recebem com frequência e-mails suspeitos, alertas de firewall e
relatórios com IPs e links maliciosos. Verificar cada indicador manualmente em vários
sites é lento, não deixa registro do que já foi analisado e consome rapidamente o
limite gratuito das APIs de reputação.

O **IOC Check** resolve isso em uma única aplicação web que roda no seu computador:

- 🔎 verifica **até 50 indicadores de uma vez**, inclusive no formato "desarmado" usado
  em relatórios (`hxxp://site[.]com`, `1.2.3[.]4`);
- 📚 cruza com uma **base local** que você mesmo monta, com severidade, tags e
  **prazo de expiração** para cada IOC;
- 🌐 consulta até **sete fontes externas**: VirusTotal, AbuseIPDB, ThreatFox,
  Hybrid Analysis, URLScan.io, MxToolbox e IPinfo;
- ⚡ guarda os resultados em **cache com data de armazenamento e de expiração**,
  evitando chamadas repetidas às APIs;
- 🕓 registra **todo o histórico** de consultas com os dados completos de cada fonte e os prints,
  e exporta só as consultas e o conteúdo que você escolher (CSV, JSON e imagens).

> Projeto desenvolvido para a disciplina **Projeto de Extensão em Software Fullstack**,
> integrando front-end, back-end e banco de dados.

## Funcionalidades

| Tela | O que faz |
|---|---|
| **Painel** | Busca rápida e o **hub de fontes conectadas** (escudo do IOC Check ligado às 8 fontes, com o estado de cada uma: ativa, pausada pelo limite gratuito ou sem chave), números de consultas, cache e base, gráfico dos últimos 14 dias, atividade recente por dia, distribuição por veredito e tipo e dicas contextuais |
| **Verificar** | Detecção automática do tipo, normalização, veredito consolidado com score de 0 a 100, detalhe fonte por fonte com link para o relatório original e atalho para adicionar o indicador à sua base |
| **Minha base** | Cadastro, edição e exclusão de IOCs com severidade, tags, fonte e validade; filtros (ativos, expirados, vencendo em 7 dias, desativados); renovação; remoção dos expirados; botão **Limpar base**; botão **Detalhes** com os dados do IOC, a última verificação completa (fontes, prints e evidências) e as consultas anteriores |
| **Histórico** | Todas as consultas com os **dados completos e os prints** (mesmo depois que o cache expira); detalhes de cada consulta; filtros; seleção de consultas; exportação escolhendo o conteúdo (resumo CSV, fontes CSV, JSON, prints de evidência e das páginas); exclusão de selecionadas; limpeza |
| **Configurações** | Chaves de API (mascaradas, com teste de conexão), ativar/desativar cada fonte, tempo que cada IOC pesquisado fica no **cache** (padrão 24h) com o resumo do cache, validade padrão dos IOCs, tempo limite e a seção **Meus dados** |
| **Logs** | Registro de tudo o que a aplicação fez: suas ações (verificar, cadastrar, exportar, configurar) e cada chamada às APIs das fontes, com endereço, parâmetros, código HTTP, tempo e o começo da resposta; filtros, busca, exportação em JSON e limpeza. Os cabeçalhos com as chaves nunca são gravados e qualquer chave que apareça numa resposta é mascarada |

## Tecnologias

| Camada | Tecnologias |
|---|---|
| **Front-end** | HTML5, CSS3 (layout responsivo, variáveis CSS), JavaScript (Fetch API), templates Jinja2, fonte Poppins |
| **Back-end** | Python 3, Flask 3 (API REST com Blueprints), Requests (integração com APIs externas), python-dotenv |
| **Banco de dados** | SQLite com SQLAlchemy / Flask-SQLAlchemy (ORM) |
| **Testes** | pytest, com as APIs externas simuladas (sem acesso à rede) |

## Estrutura do projeto

```
IOC Check/
├── frontend/                   # Interface (o que roda no navegador)
│   ├── templates/              # Páginas HTML (Jinja2)
│   │   ├── base.html           #   layout com barra lateral
│   │   ├── dashboard.html      #   Painel
│   │   ├── check.html          #   Verificar
│   │   ├── iocs.html           #   Minha base
│   │   ├── history.html        #   Histórico
│   │   ├── settings.html       #   Configurações
│   │   └── logs.html           #   Logs da aplicação
│   └── static/
│       ├── css/style.css       # Estilo e paleta de cores
│       └── js/                 # Um script por página + api.js (funções compartilhadas)
│                               #   e sources.js (ícones das fontes)
│
├── backend/                    # Servidor, regras de negócio e banco
│   ├── app/
│   │   ├── __init__.py         # create_app(): configura Flask, banco, rotas e segurança
│   │   ├── config.py           # Variáveis de ambiente (.env)
│   │   ├── models.py           # Tabelas: iocs, cache_entries, query_logs, settings, provider_quota, app_logs
│   │   ├── ioc_utils.py        # Detecção de tipo, refang e normalização
│   │   ├── routes/             # Endpoints da API REST e páginas
│   │   └── services/
│   │       ├── checker.py      #   fluxo de verificação e veredito
│   │       ├── cache.py        #   leitura, gravação e expiração do cache
│   │       ├── providers.py    #   integrações com as 7 fontes externas
│   │       ├── quota.py        #   respeito aos limites dos planos gratuitos
│   │       ├── report_parsers.py #   leitura detalhada dos relatórios (downloads, redirecionamentos...)
│   │       ├── evidence.py     #   evidências em imagem (PNG) e em texto, com marca d'água
│   │       ├── history.py      #   histórico completo e exportação
│   │       ├── media.py        #   cópia local das capturas de tela do URLScan.io
│   │       ├── activity.py     #   registro de ações e chamadas às APIs (tela Logs)
│   │       ├── page_capture.py #   print da página pública de cada fonte
│   │       └── settings.py     #   configurações salvas no banco
│   ├── tests/                  # Testes automatizados (pytest)
│   ├── instance/               # Banco SQLite (criado automaticamente, fora do Git)
│   ├── run.py                  # Inicia o servidor
│   ├── seed.py                 # Carrega IOCs de demonstração (opcional)
│   ├── requirements.txt
│   ├── pytest.ini
│   └── .env.example
│
├── iniciar.bat                 # Inicia o app em segundo plano com dois cliques (Windows)
├── parar.bat                   # Encerra o app (o mesmo que o botão "⏻ Encerrar")
├── iniciar.sh                  # Inicia o app com um comando (Linux/macOS)
├── .gitattributes              # Fim de linha correto dos scripts (.bat em CRLF, .sh em LF)
└── README.md
```

### Arquitetura

```
┌─────────────────────────────┐        fetch() + JSON        ┌──────────────────────────────┐
│ FRONT-END  (frontend/)      │ ───────────────────────────▶ │ BACK-END  (backend/app)      │
│ HTML · CSS · JavaScript     │ ◀─────────────────────────── │ Flask · API REST /api/*      │
└─────────────────────────────┘                              └──────────────┬───────────────┘
                                                                            │
                                 ┌──────────────────────────────────────────┼──────────────────────┐
                                 ▼                                          ▼                      ▼
                     ┌──────────────────────┐              ┌──────────────────────────┐  ┌──────────────────┐
                     │ SQLite (SQLAlchemy)  │              │ APIs externas            │  │ Cache de         │
                     │ iocs · query_logs ·  │              │ VirusTotal · AbuseIPDB · │  │ consultas        │
                     │ cache_entries ·      │              │ ThreatFox · Hybrid       │  │ (cache_entries)  │
                     │ settings             │              │ Analysis · URLScan.io    │  │                  │
                     └──────────────────────┘              └──────────────────────────┘  └──────────────────┘
```

O Flask serve as páginas da pasta `frontend/` e expõe a API em `/api/*`. O JavaScript
de cada página consome essa API com `fetch()` e monta a interface.

## Como executar

**Requisitos:** Python 3.10 ou superior ([download](https://www.python.org/downloads/) —
no Windows, marque "Add Python to PATH" durante a instalação).

```bash
git clone https://github.com/ClaDutra/IOC-Check.git
```

### Jeito fácil: um clique

- **Windows:** dê dois cliques em **`iniciar.bat`**, na pasta do projeto.
- **Linux/macOS:** execute `sh iniciar.sh`.

O script confere o Python, cria o ambiente virtual e instala as dependências (só na
primeira vez), inicia o servidor **em segundo plano** e abre o navegador em
**http://localhost:5000**. A janela do CMD fecha sozinha e o app continua rodando, sem
janela aberta. Se o IOC Check já estiver aberto, o script o reinicia para carregar a
versão mais recente do código.

Para encerrar, clique em **⏻ Encerrar** na barra lateral ou dê dois cliques em
**`parar.bat`**. As mensagens do servidor ficam em `backend/instance/ioc_check.log`.

> **Levando para outro computador:** não copie nem compacte a pasta `.venv` — ela só
> funciona no computador onde foi criada. Se ela vier junto por engano, o `iniciar.bat`
> detecta, recria o ambiente e reinstala as dependências sozinho. Requer Python 3.10+
> **64 bits** com a opção "Add Python to PATH".

### Passo a passo manual

```bash
python -m venv .venv
```

No Windows:

```bash
.venv\Scripts\activate
```

No Linux/macOS:

```bash
source .venv/bin/activate
```

```bash
pip install -r backend/requirements.txt
```

```bash
python backend/run.py
```

Acesse **http://localhost:5000**. A base começa vazia para você montar a sua. Para
personalizar a configuração, copie `backend/.env.example` para `backend/.env`.

Para ver o sistema com dados de demonstração, carregue os exemplos:

```bash
python backend/seed.py
```

Os exemplos usam faixas de IP reservadas para documentação (RFC 5737), domínios
`.example` (RFC 2606) e os hashes do arquivo de teste EICAR. Nenhum deles é uma ameaça
real, e podem ser apagados com **Limpar base**.

## Configuração

As chaves de API e os prazos podem ser definidos na tela **Configurações** (salvos no
banco, com prioridade) ou no arquivo `backend/.env`:

| Variável | Padrão | Descrição |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | — | Chave do VirusTotal |
| `ABUSEIPDB_API_KEY` | — | Chave do AbuseIPDB |
| `THREATFOX_API_KEY` | — | Auth-Key do abuse.ch (ThreatFox) |
| `HYBRID_ANALYSIS_API_KEY` | — | Chave do Hybrid Analysis |
| `URLSCAN_API_KEY` | — | Chave do URLScan.io (opcional) |
| `MXTOOLBOX_API_KEY` | — | Chave da MxToolbox |
| `IPINFO_API_KEY` | — | Token do IPinfo |
| `CACHE_TTL_HOURS` | `24` | Validade de um resultado no cache |
| `CACHE_ERROR_TTL_MINUTES` | `10` | Validade quando alguma fonte falhou |
| `IOC_DEFAULT_EXPIRATION_DAYS` | `90` | Validade padrão de novos IOCs (`0` = nunca expira) |
| `PROVIDER_TIMEOUT` | `8` | Tempo limite por fonte, em segundos |
| `DATABASE_URL` | `backend/instance/ioc_check.db` | Caminho alternativo do banco |
| `PORT` | `5000` | Porta do servidor |

## Fontes de dados

| Fonte | Tipos consultados | Chave | Limite do plano gratuito |
|---|---|---|---|
| **Base local** | todos | — | — |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | IP, domínio, URL, hashes | obrigatória | 4 consultas/min e 500/dia, uso pessoal e não comercial |
| [AbuseIPDB](https://www.abuseipdb.com/register) | IP | obrigatória | 1.000 consultas/dia |
| [ThreatFox](https://auth.abuse.ch/) | IP, domínio, URL, hashes | obrigatória (Auth-Key) | uso justo (*fair use*), sem fins comerciais |
| [Hybrid Analysis](https://www.hybrid-analysis.com/signup) | hashes (MD5, SHA1, SHA256) | obrigatória | chave *restricted*: só buscas, 200/min e 2.000/hora |
| [URLScan.io](https://urlscan.io/user/signup) | IP, domínio, URL, SHA256 | opcional | 120 buscas/min com chave; não copiar a base em massa |
| [MxToolbox](https://mxtoolbox.com/User/Api/) | domínio, URL e e-mail (MX, SPF, DMARC); IP (PTR) | obrigatória | 64 consultas DNS/dia e nenhuma de rede: cada domínio usa 3 consultas e cada IP, 1; a blacklist (consulta de rede) não é usada |
| [IPinfo](https://ipinfo.io/signup) | IP | obrigatória (token) | IPinfo Lite gratuito: ASN, organização e país; o IOC Check limita a 60/min |

Todas têm plano gratuito. Sem nenhuma chave, o IOC Check funciona com a base local e o
URLScan.io. Use o botão **Testar** em Configurações para validar cada chave.

### Respeito aos limites gratuitos

Toda chamada às fontes externas passa pelo controle de cota
([`services/quota.py`](backend/app/services/quota.py)), que:

- conta as consultas de cada fonte por minuto e por dia e **não chama a API** quando o
  limite gratuito é atingido (ex.: a 5ª consulta ao VirusTotal no mesmo minuto);
- lê os cabeçalhos de limite que as próprias APIs devolvem (`X-RateLimit-*`,
  `X-Rate-Limit-*`, `api-limits`) e mostra o saldo real da conta em **Configurações**;
- ao receber **HTTP 429** ("limite atingido"), **pausa a fonte** até o horário de
  `Retry-After` (no VirusTotal, até a cota diária zerar), em vez de continuar insistindo;
- guarda no cache, por apenas 10 minutos, os resultados afetados por uma pausa, para
  consultar de novo assim que a fonte for liberada.

A Hybrid Analysis consulta só hashes porque as chaves gratuitas (*restricted*) não têm
acesso à busca por IP, domínio ou URL.

### Análise detalhada de cada fonte

Além do veredito, as fontes trazem o **comportamento** do indicador. Os **alertas**
aparecem ao lado do resumo, e o restante fica em **"Mais detalhes"**:

| Fonte | Alertas | Detalhes |
|---|---|---|
| **URLScan.io** (relatório completo da varredura mais recente) | download de executável ou arquivo compactado, redirecionamentos, marca imitada (phishing), risco apontado pelos mecanismos de IA, votos da comunidade, página sem HTTPS, domínio recém-registrado, site servido direto por IP | **captura de tela da página** (miniatura clicável), URL final, título, status HTTP, tipo de conteúdo, IP e localização, ASN, DNS reverso, servidor, requisições, domínios e IPs contatados, **arquivos baixados** (com link para verificar o hash) e **cadeia de redirecionamentos** |
| **VirusTotal** | marca imitada, categoria de risco (phishing, malware...), votos e reputação negativa, domínio criado há poucos dias, classificação da ameaça, regras Sigma graves | **mecanismos que detectaram** e o nome dado à ameaça; IP: ASN, bloco de rede, país, registro regional; domínio: registrador, data de criação, IPs do DNS, certificado HTTPS; URL: título, URL final e redirecionamentos, status HTTP; arquivo: nome, tipo, tamanho, primeiro envio, **veredito das sandboxes** e **regras YARA** |
| **AbuseIPDB** | nó de saída Tor, datacenter/hospedagem, lista de permissão, **categorias de abuso** mais denunciadas | país, provedor, domínio, hostnames, tipo de uso, versão do IP, confiança de abuso, denunciantes distintos, primeira e última denúncia, **países que mais denunciaram** e as 5 denúncias mais recentes |
| **MxToolbox** | falhas e avisos nas verificações de MX, SPF e DMARC; DMARC com política `none` (e-mail falsificado não é bloqueado) | servidores MX (ou "MX nulo": o domínio não recebe e-mail), registros SPF e DMARC, DNS reverso (PTR) do IP e a lista de verificações aprovadas, com aviso ou com falha |
| **IPinfo** | — | ASN, organização dona do bloco, domínio do provedor, país e continente |
| **ThreatFox** | servidor comprometido, **IOCs de malware hospedados no mesmo IP ou domínio** | tipo de ameaça, malware e apelidos, ficha no Malpedia, primeira e última vez visto, quem reportou, referência, avistamentos, etiquetas e **amostras de malware** (com link para verificar o hash) |
| **Hybrid Analysis** | veredito da sandbox, **família do malware**, arquivo não executável no ambiente | tipo, tamanho, % de detecção nos antivírus, nomes de envio, datas, etiquetas, votos, scanners consultados e **endereços de onde o arquivo foi baixado** |

Esses sinais também elevam o veredito: uma página que entrega um executável direto
de um endereço IP, ou que imita uma marca, é classificada como **maliciosa** mesmo
que a varredura não tenha sido marcada assim.

### Prints de evidência

#### 📸 Print da página da fonte

Em cada fonte com página pública (VirusTotal, AbuseIPDB, ThreatFox, Hybrid Analysis,
URLScan.io e IPinfo) há o botão **📸 Print da página**. Ao clicar, o IOC Check abre a página da
fonte para aquele indicador (ex.: `abuseipdb.com/check/<IP>`) numa **janela do Edge ou
do Chrome**, tira o print da página inteira e fecha a janela. O print aparece em
miniatura com os botões **📋 Copiar print da página** (cola com Ctrl+V), **⬇ Baixar** e
**Ver**, e continua disponível nas próximas consultas do mesmo indicador.

- **Verificação humana:** AbuseIPDB e ThreatFox protegem as páginas com a verificação
  "Confirme que é humano" (Cloudflare). O IOC Check **não contorna** essa proteção: quando
  ela aparece, a janela fica aberta para **você** clicar na caixa; assim que a página real
  carrega, o print é feito sozinho. Os cookies ficam no perfil do navegador do IOC Check
  (`backend/instance/navegador`), então as próximas capturas costumam passar direto.
- **Versão logada:** se fizer login no site nessa janela (por exemplo, no AbuseIPDB), os
  próximos prints saem com a sua conta, com o painel completo da página.
- **Limites respeitados:** o print só é feito quando você pede — equivale a abrir a página
  uma vez, como faria manualmente. Avisos de cookies são apenas ocultados na imagem.

#### 📋 Resumo e evidência completa

- **📋 Copiar evidência completa** (no topo do resultado): uma imagem com o veredito final
  e o resumo de todas as fontes;
- **📋 Copiar resumo** (em cada fonte): um cartão gerado com os dados da API — informações
  principais, alertas, listas de detalhes e o link da fonte. No URLScan.io, o cartão
  inclui a captura de tela do site analisado e a cadeia de redirecionamentos
  (campo `data.redirects` do relatório).

### Evidência em texto, links diretos e marca d'água

- Toda evidência pode ser coletada **em texto**: **📝 Copiar texto** / **⬇ TXT** ao lado de cada
  print (resumo de uma fonte, evidência completa e print da página). No print da página, o
  texto visível do site é salvo junto com a imagem.
- Mesmo quando a consulta a uma fonte falha (erro, limite gratuito, sem chave ou desativada),
  o resultado traz o **link direto para a página da fonte já com o IOC**, e o botão 📸 Print
  da página continua disponível.
- Os prints de evidência, os prints de página e os textos levam a marca d'água
  **github.com/ClaDutra/IOC-Check**, que também aparece no canto da aplicação.
- O menu lateral pode ser **recolhido** (botão ‹ no topo), ficando só com os ícones; a escolha
  é lembrada entre as páginas.

### Modo escuro

O botão **🌙 Modo escuro / ☀️ Modo claro**, na barra lateral, alterna o tema. Na primeira
visita o IOC Check segue o tema do sistema operacional; depois, a escolha fica salva no
navegador.

## Como funciona

### Fluxo de uma verificação

1. O indicador é **normalizado** ("refang", letras minúsculas) e seu **tipo** é detectado.
2. O sistema procura um resultado **válido no cache**. Se encontrar, devolve-o sem chamar as APIs.
3. Caso contrário, consulta a **base local** e as **fontes externas** ativas.
4. O **veredito final** é o mais grave entre as fontes que trouxeram informação.
5. O resultado é gravado no cache com `stored_at` (armazenamento) e `expires_at` (expiração).
6. A consulta é registrada no **histórico**.

### Regra de veredito

| Fonte | Malicioso | Suspeito |
|---|---|---|
| Base local (IOC ativo e dentro da validade) | severidade crítica ou alta | severidade média ou baixa |
| VirusTotal | 3+ mecanismos maliciosos | 1–2 maliciosos ou 2+ suspeitos |
| AbuseIPDB | confiança ≥ 75% | confiança ≥ 25% |
| ThreatFox | registro com confiança ≥ 50% | registro com confiança < 50% |
| Hybrid Analysis | veredito "malicious" no `/overview` | veredito "suspicious" no `/overview` |
| URLScan.io | 2+ varreduras maliciosas, marca imitada, ou executável servido por IP / apontado pelos mecanismos | 1 varredura maliciosa, download de executável, ou risco apontado pelos mecanismos de IA |

MxToolbox e IPinfo trazem **contexto** (configuração de e-mail do domínio e dono do IP), não
reputação: aparecem como "sem veredito" e não alteram o veredito final.

URLs e e-mails também são comparados com o **domínio** cadastrado na base local.

### Cache e histórico

- O cache funciona nos bastidores (não tem tela própria): todo IOC pesquisado fica guardado
  pelo tempo definido em **Configurações** (padrão 24 horas), reduzido para 10 minutos
  quando alguma fonte falha. O resumo e a limpeza do cache ficam em Configurações.
- O **histórico** guarda uma cópia completa do resultado de cada consulta, a captura de tela
  do URLScan.io (copiada para `instance/midias` no momento da consulta) e os prints das
  páginas das fontes (`instance/capturas`, um por consulta). Assim nada se perde quando o
  cache expira ou é esvaziado.
- Os **prints de página** seguem o mesmo prazo do cache: um print tirado dentro do prazo é
  reaproveitado nas próximas consultas do mesmo indicador (copiado para a nova consulta,
  mantendo a data original da captura). Depois do prazo, ou ao forçar uma nova consulta,
  basta tirar um novo print.
- Alterar um IOC invalida o cache dos indicadores relacionados.
- Limpar a base remove do cache só os resultados que vieram da base local.
- Mudar chaves ou ativar/desativar fontes limpa o cache.
- Um resultado vindo da base local nunca dura mais que o IOC que o gerou.

### Prazo de expiração dos IOCs

IPs e domínios maliciosos mudam de dono com o tempo, e um IOC antigo pode gerar falso
positivo. Por isso cada IOC tem validade (7 dias, 30 dias, 90 dias, 6 meses, 1 ano, data
específica ou "nunca expira"). Depois do prazo, ele aparece como **Expirado** e deixa de
ser considerado nas verificações, mas pode ser renovado com um clique.

### Modelo de dados

| Tabela | Campos |
|---|---|
| `iocs` | `id, value, ioc_type, severity, description, tags, source, active, expires_at, created_at, updated_at` |
| `cache_entries` | `id, indicator, ioc_type, verdict, score, results_json, stored_at, expires_at, hits` |
| `query_logs` | `id, indicator, ioc_type, verdict, score, from_cache, cache_stored_at, cache_expires_at, results_json, queried_at` |
| `settings` | `key, value, updated_at` |
| `provider_quota` | `provider, day, day_calls, window_start, window_calls, blocked_until, remote_limit, remote_remaining, remote_window` |

## API REST

| Método | Rota | Descrição |
|---|---|---|
| `POST` | `/api/check` | Verifica indicadores: `{"indicators": "...", "force_refresh": false}` |
| `GET` | `/api/iocs` | Lista a base (filtros `q`, `type`, `severity`, `status`, `page`) |
| `POST` | `/api/iocs` | Cadastra um IOC (`expires_at`: data ISO 8601 ou `null`) |
| `GET` `PUT` `DELETE` | `/api/iocs/<id>` | Detalha, edita ou exclui um IOC |
| `POST` | `/api/iocs/purge-expired` | Remove os IOCs expirados |
| `DELETE` | `/api/iocs` | Limpa a base inteira |
| `GET` | `/api/history` | Histórico (filtros `q`, `verdict`, `type`, `source`) |
| `GET` `DELETE` | `/api/history/<id>` | Detalhes completos de uma consulta (com os prints) ou exclusão |
| `POST` | `/api/history/delete` | Exclui as consultas selecionadas: `{"ids": [1, 2]}` |
| `GET` | `/api/history/export` | Exporta: `ids=1,2` (sem ids, o filtro atual) e `include=summary,sources,json,evidence,pages` |
| `DELETE` | `/api/history` | Limpa o histórico (com os prints guardados) |
| `GET` | `/api/cache/summary` | Resumo do cache (válidas, expiradas, reusos, validade) |
| `GET` | `/api/cache` | Entradas do cache (filtros `q`, `status`) |
| `DELETE` | `/api/cache/<id>` | Remove uma entrada |
| `POST` | `/api/cache/purge-expired` | Remove entradas expiradas |
| `DELETE` | `/api/cache` | Esvazia o cache |
| `GET` `PUT` | `/api/settings` | Lê ou salva configurações: `{"values": {...}, "clear": [...]}` |
| `POST` | `/api/settings/providers/<id>/test` | Testa a conexão com uma fonte |
| `GET` | `/api/stats` | Estatísticas do Painel |
| `GET` | `/api/health` | Status do servidor e das fontes |
| `POST` | `/api/capture/<id>?provider=<fonte>` | Abre a página da fonte e salva o print (pode aguardar a verificação humana) |
| `GET` | `/api/capture/<id>.png?provider=<fonte>` | Print da página da fonte (`&download=1` para baixar) |
| `GET` | `/api/evidence/<id>.png` | Print de evidência de uma consulta do histórico (`?provider=<fonte>` para uma fonte só; `&download=1` para baixar) |
| `GET` | `/api/evidence/screenshot?url=` | Captura de tela do URLScan.io pela cópia local |
| `GET` | `/api/evidence/<id>.txt` | Evidência em texto (`?provider=<fonte>`; `&download=1`) |
| `GET` | `/api/capture/<id>.txt?provider=<fonte>` | Texto da página da fonte salvo junto com o print |
| `GET` | `/api/iocs/<id>/details` | IOC da base + última verificação completa e consultas anteriores |
| `GET` `DELETE` | `/api/logs` | Logs da aplicação (filtros `category`, `level`, `source`, `q`) ou limpeza |
| `GET` | `/api/logs/export` | Exporta os logs filtrados em JSON |
| `POST` | `/api/system/shutdown` | Encerra o IOC Check (botão da barra lateral) |

Requisições `POST`, `PUT` e `DELETE` exigem o cabeçalho `X-Requested-With: IOCCheck`
(veja [Segurança](#segurança)).

Exemplo de verificação via linha de comando:

```bash
curl -X POST http://localhost:5000/api/check -H "Content-Type: application/json" -H "X-Requested-With: IOCCheck" -d "{\"indicators\": \"8.8.8.8\"}"
```

## Testes

```bash
python -m pytest backend -v
```

Os testes cobrem detecção de tipos e refang, cache (reuso, expiração, invalidação e
limpeza), base local, prazo de expiração dos IOCs, histórico completo e exportação seletiva (CSV, JSON e ZIP com imagens),
estatísticas, configurações, proteção contra requisições de outros sites e a
interpretação das respostas de cada fonte externa (com respostas reais salvas como amostra,
sem acesso à rede), o respeito aos limites dos planos gratuitos e a geração dos prints de evidência.

## Segurança

O IOC Check é uma ferramenta **pessoal**, feita para rodar no próprio computador, e
por isso não tem tela de login. Para proteger seus dados:

- o servidor escuta apenas em `127.0.0.1`, então outras máquinas da rede não acessam;
- toda requisição que altera dados exige o cabeçalho `X-Requested-With: IOCCheck`. Como
  o navegador não permite que um site de outra origem envie esse cabeçalho, uma página
  maliciosa aberta em outra aba não consegue, por exemplo, apagar sua base;
- IPs privados e reservados **nunca** são enviados às fontes externas;
- as chaves de API aparecem mascaradas na interface. Elas ficam no banco local
  (`backend/instance/`), que está no `.gitignore` e não vai para o GitHub.

> ⚠️ Não exponha o servidor na internet nem altere o `host` para `0.0.0.0`: sem login,
> qualquer pessoa com acesso à porta poderia ver e alterar sua base.
