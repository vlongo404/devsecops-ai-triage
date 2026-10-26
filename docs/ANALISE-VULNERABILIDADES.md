# Análise de Vulnerabilidades

Data da análise: 26/10/2026 · Versão analisada: 1.0.0

Este documento registra (1) o modelo de ameaças, (2) as vulnerabilidades **realmente encontradas** pelas
ferramentas rodadas durante o desenvolvimento, com evidência antes/depois, e (3) quais verificações rodam
apenas no pipeline do GitHub Actions.

## 1. Modelo de ameaças (STRIDE resumido)

| Ameaça | Cenário | Controle implementado | Onde |
|---|---|---|---|
| **S**poofing | Chamador anônimo abusa da API | Rate limiting por IP; em produção, colocar autenticação no reverse proxy | `app/security.py` |
| **T**ampering | Prompt injection altera o comportamento do modelo | Heurística de bloqueio + dado delimitado em `<incidente>` + prompt de sistema defensivo | `security.py`, `prompts/runtime/triage_system.md` |
| **R**epudiation | Não saber quem pediu o quê | `request_id` por requisição e logs estruturados | `main.py` |
| **I**nformation disclosure | PII vai para o provedor de LLM / logs | Redação de CPF, CNPJ, e-mail, telefone e cartão antes do LLM; logs só com hash | `redact_pii`, `main.py` |
| **D**enial of service | Payload gigante ou rajadas (consumo de tokens) | Limite de 8 KB no body, 2000 caracteres de texto, token bucket, timeout no provedor | `main.py`, `llm.py` |
| **E**levation of privilege | Container comprometido vira root | Usuário não-root, `read_only`, `cap_drop: ALL`, `no-new-privileges` | `Dockerfile`, `docker-compose.yml` |
| Saída do LLM (LLM05) | Modelo devolve HTML/JS ou valor fora do contrato | Validação estrita de enums e remoção de `<` `>` | `validate_model_output` |

## 2. Achados reais e correções

Ferramentas executadas localmente: **Ruff 0.14.0**, **Bandit 1.8.6** (SAST) e **pip-audit 2.9.0** (SCA).
Os resultados brutos estão em [`docs/evidencias/`](evidencias/).

| # | Achado | Ferramenta | Severidade | Status |
|---|---|---|---|---|
| 1 | Dependência `flask 3.1.2` com vulnerabilidade conhecida **PYSEC-2026-2151** (corrigida na 3.1.3) | pip-audit | Conforme o advisory | ✅ Corrigido: `flask==3.1.3` |
| 2 | `urllib.request.urlopen` aceita esquemas inesperados (`file:`, custom) — **B310 / CWE-22** | Bandit | Média (confiança alta) | ✅ Mitigado: `LLM_API_URL` só aceita `http`/`https` e exige host (valida no `__init__`); exceção documentada com `# nosec B310` |
| 3 | Cabeçalho `Server: gunicorn` revela a tecnologia (fingerprinting) | Verificação manual com `curl -I` | Baixa | ✅ Corrigido em `gunicorn.conf.py` (`Server: webserver`) |
| 4 | Variáveis de loop não usadas (B007) e linha longa (E501) | Ruff | Qualidade | ✅ Corrigido |

### Evidência dos achados 1 e 2

Antes (`docs/evidencias/pip-audit-antes.txt`):

```
Found 1 known vulnerability in 1 package
Name  Version ID              Fix Versions
----- ------- --------------- ------------
flask 3.1.2   PYSEC-2026-2151 3.1.3
```

Depois (`docs/evidencias/pip-audit.txt`): `No known vulnerabilities found`.

Bandit antes (`bandit-antes.txt`): 1 issue de severidade Média (B310, `app/llm.py`).
Bandit depois (`bandit.txt`): 0 issues (Low 0, Medium 0, High 0).

Testes (`pytest.txt`): **22 passed**, cobertura **86,7 %** (meta mínima do pipeline: 85 %).

## 3. Verificações que rodam no pipeline (não executadas localmente)

Estas etapas estão definidas em `.github/workflows/devsecops.yml` e geram evidência na aba **Actions** e
**Security** do repositório após o primeiro push. Elas **não** foram executadas na máquina de desenvolvimento
(o daemon do Docker não estava disponível), então os resultados delas devem ser coletados do GitHub:

| Etapa | Ferramenta | O que detecta |
|---|---|---|
| Secrets | Gitleaks | Chaves e tokens commitados |
| SAST | CodeQL | Falhas de fluxo de dados (injeção, SSRF...) |
| IaC/Docker | Hadolint, Trivy config | Más práticas no Dockerfile e no compose |
| Imagem | Trivy | CVEs no sistema base e nas bibliotecas da imagem |
| SBOM | Syft (CycloneDX) | Inventário de componentes (cadeia de suprimentos) |
| Assinatura | Cosign keyless | Integridade e procedência da imagem |
| DAST | OWASP ZAP baseline | Falhas na aplicação em execução (cabeçalhos, cookies...) |

**Para o relatório/slides:** depois do primeiro push, tire prints das abas Actions e Security e anexe-os.

## 4. Riscos residuais aceitos

- A heurística de prompt injection é por palavras-chave; ataques sofisticados podem passar. Mitigação em
  camadas: prompt defensivo, validação da saída e decisão final sempre humana.
- O rate limiter é em memória (por processo): em múltiplas réplicas, usar Redis ou limitar no gateway.
- Não há autenticação na aplicação de demonstração: em produção, exigir OIDC/API key no reverse proxy.
- Redação de PII é baseada em regex (CPF/CNPJ/e-mail/telefone/cartão) e não cobre nomes próprios.
