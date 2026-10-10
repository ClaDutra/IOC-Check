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
- 🌐 consulta até **cinco fontes externas**: VirusTotal, AbuseIPDB, ThreatFox,
  Hybrid Analysis e URLScan.io;
- ⚡ guarda os resultados em **cache com data de armazenamento e de expiração**,
  evitando chamadas repetidas às APIs;
- 🕓 registra **todo o histórico** de consultas, com exportação em CSV.

> Projeto desenvolvido para a disciplina **Projeto de Extensão em Software Fullstack**,
> integrando front-end, back-end e banco de dados.

## Funcionalidades

| Tela | O que faz |
|---|---|
| **Painel** | Estatísticas, gráfico de consultas dos últimos 14 dias, atividade recente agrupada por dia, distribuição por veredito e tipo, status das fontes e dicas contextuais |
| **Verificar** | Detecção automática do tipo, normalização, veredito consolidado com score de 0 a 100, detalhe fonte por fonte com link para o relatório original e atalho para adicionar o indicador à sua base |
| **Minha base** | Cadastro, edição e exclusão de IOCs com severidade, tags, fonte e validade; filtros (ativos, expirados, vencendo em 7 dias, desativados); renovação; remoção dos expirados; botão **Limpar base** |
| **Histórico** | Todas as consultas, indicando se vieram do cache e quando o resultado foi armazenado; filtros; exportação CSV; limpeza |
| **Cache** | Entradas armazenadas com data de armazenamento, expiração e número de reusos; detalhes; remoção de expirados ou de todo o cache |
| **Configurações** | Chaves de API (mascaradas, com teste de conexão), ativar/desativar cada fonte, validade do cache, validade padrão dos IOCs, tempo limite e a seção **Meus dados** |

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
│   │   ├── cache.html          #   Cache
│   │   └── settings.html       #   Configurações
│   └── static/
│       ├── css/style.css       # Estilo e paleta de cores
│       └── js/                 # Um script por página + api.js (funções compartilhadas)
│
├── backend/                    # Servidor, regras de negócio e banco
│   ├── app/
│   │   ├── __init__.py         # create_app(): configura Flask, banco, rotas e segurança
│   │   ├── config.py           # Variáveis de ambiente (.env)
│   │   ├── models.py           # Tabelas: iocs, cache_entries, query_logs, settings
│   │   ├── ioc_utils.py        # Detecção de tipo, refang e normalização
│   │   ├── routes/             # Endpoints da API REST e páginas
│   │   └── services/
│   │       ├── checker.py      #   fluxo de verificação e veredito
│   │       ├── cache.py        #   leitura, gravação e expiração do cache
│   │       ├── providers.py    #   integrações com as 5 fontes externas
│   │       ├── report_parsers.py #   leitura detalhada dos relatórios (downloads, redirecionamentos...)
│   │       └── settings.py     #   configurações salvas no banco
│   ├── tests/                  # Testes automatizados (pytest)
│   ├── instance/               # Banco SQLite (criado automaticamente, fora do Git)
│   ├── run.py                  # Inicia o servidor
│   ├── seed.py                 # Carrega IOCs de demonstração (opcional)
│   ├── requirements.txt
│   ├── pytest.ini
│   └── .env.example
│
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

**Requisitos:** Python 3.10 ou superior.

**1. Clone o repositório**

```bash
git clone https://github.com/SEU-USUARIO/ioc-check.git
```

```bash
cd ioc-check
```

**2. Crie e ative o ambiente virtual**

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

**3. Instale as dependências**

```bash
pip install -r backend/requirements.txt
```

**4. (Opcional) Crie o arquivo de configuração**

No Windows:

```bash
copy backend\.env.example backend\.env
```

No Linux/macOS:

```bash
cp backend/.env.example backend/.env
```

**5. Inicie o servidor**

```bash
python backend/run.py
```

Acesse **http://localhost:5000**. A base começa vazia para você montar a sua.

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
| `CACHE_TTL_HOURS` | `24` | Validade de um resultado no cache |
| `CACHE_ERROR_TTL_MINUTES` | `10` | Validade quando alguma fonte falhou |
| `IOC_DEFAULT_EXPIRATION_DAYS` | `90` | Validade padrão de novos IOCs (`0` = nunca expira) |
| `PROVIDER_TIMEOUT` | `8` | Tempo limite por fonte, em segundos |
| `DATABASE_URL` | `backend/instance/ioc_check.db` | Caminho alternativo do banco |
| `PORT` | `5000` | Porta do servidor |

## Fontes de dados

| Fonte | Tipos consultados | Chave | O que informa |
|---|---|---|---|
| **Base local** | todos | — | IOCs que você cadastrou |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | IP, domínio, URL, hashes | obrigatória | Detecções de dezenas de antivírus |
| [AbuseIPDB](https://www.abuseipdb.com/register) | IP | obrigatória | Denúncias de abuso da comunidade |
| [ThreatFox](https://auth.abuse.ch/) | IP, domínio, URL, hashes | obrigatória | IOCs de malware, botnets e C2 |
| [Hybrid Analysis](https://www.hybrid-analysis.com/signup) | IP, domínio, URL, hashes | obrigatória | Relatórios de sandbox |
| [URLScan.io](https://urlscan.io/user/signup) | IP, domínio, URL, SHA256 | opcional | Varreduras públicas de sites |

Todas têm plano gratuito. Sem nenhuma chave, o IOC Check funciona com a base local e o
URLScan.io. Use o botão **Testar** em Configurações para validar cada chave.

### Análise detalhada (URLScan.io e AbuseIPDB)

Além do veredito, essas duas fontes trazem o **comportamento** do indicador. Os
**alertas** aparecem ao lado do resumo, e o restante fica em **"Mais detalhes"**:

| Fonte | Alertas | Detalhes |
|---|---|---|
| **URLScan.io** (relatório completo da varredura mais recente) | download de arquivo executável ou compactado, redirecionamentos, marca imitada (phishing), classificação dos mecanismos de IA, votos da comunidade, página sem HTTPS, domínio recém-registrado, site servido direto por IP | URL final, título, status HTTP, tipo de conteúdo, IP e localização, ASN, DNS reverso, servidor, nº de requisições, domínios e IPs contatados, captura de tela, **arquivos baixados** (nome, tamanho, tipo e SHA256, com link para verificar o hash) e **cadeia de redirecionamentos** |
| **AbuseIPDB** | nó de saída Tor, datacenter/hospedagem, lista de permissão, **categorias de abuso** mais denunciadas (força bruta, varredura de portas, phishing...) | país, provedor, domínio, hostnames, tipo de uso, denunciantes distintos, última denúncia e as **5 denúncias mais recentes** com categorias e comentários |

Esses sinais também elevam o veredito: uma página que entrega um executável direto
de um endereço IP, ou que imita uma marca, é classificada como **maliciosa** mesmo
que a varredura não tenha sido marcada assim.

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
| Hybrid Analysis | algum relatório "malicious" | algum relatório "suspicious" |
| URLScan.io | 2+ varreduras maliciosas, marca imitada, ou executável servido por IP / apontado pelos mecanismos | 1 varredura maliciosa, download de executável, ou risco apontado pelos mecanismos de IA |

URLs e e-mails também são comparados com o **domínio** cadastrado na base local.

### Cache

- Validade padrão de 24 horas, reduzida para 10 minutos quando alguma fonte falha.
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
| `query_logs` | `id, indicator, ioc_type, verdict, score, from_cache, cache_stored_at, queried_at` |
| `settings` | `key, value, updated_at` |

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
| `GET` | `/api/history/export` | Exporta o histórico em CSV |
| `DELETE` | `/api/history` | Limpa o histórico |
| `GET` | `/api/cache` | Entradas do cache + resumo (filtros `q`, `status`) |
| `GET` `DELETE` | `/api/cache/<id>` | Detalha ou remove uma entrada |
| `POST` | `/api/cache/purge-expired` | Remove entradas expiradas |
| `DELETE` | `/api/cache` | Esvazia o cache |
| `GET` `PUT` | `/api/settings` | Lê ou salva configurações: `{"values": {...}, "clear": [...]}` |
| `POST` | `/api/settings/providers/<id>/test` | Testa a conexão com uma fonte |
| `GET` | `/api/stats` | Estatísticas do Painel |
| `GET` | `/api/health` | Status do servidor e das fontes |

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
limpeza), base local, prazo de expiração dos IOCs, histórico e exportação CSV,
estatísticas, configurações, proteção contra requisições de outros sites e a
interpretação das respostas de cada fonte externa (com as APIs simuladas, sem rede).

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
