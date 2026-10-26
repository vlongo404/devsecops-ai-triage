# Conformidade

Mapeamento dos controles do projeto para frameworks de referência. A tabela mostra **onde** cada requisito
é atendido no repositório. Este é um alinhamento de projeto acadêmico, não uma certificação.

## OWASP Top 10 (2021)

| Item | Como é tratado |
|---|---|
| A01 Broken Access Control | Superfície mínima (2 rotas); autenticação delegada ao gateway (risco residual documentado) |
| A02 Cryptographic Failures | Segredos só por variável de ambiente/GitHub Secrets; Gitleaks; TLS no reverse proxy |
| A03 Injection | Entrada validada por tipo e tamanho; nenhuma consulta SQL/shell com dados do usuário |
| A04 Insecure Design | Modelo de ameaças STRIDE (`ANALISE-VULNERABILIDADES.md`) |
| A05 Security Misconfiguration | Cabeçalhos de segurança, container `read_only`, `cap_drop: ALL`, Hadolint e Trivy config |
| A06 Vulnerable Components | pip-audit (`--strict`), Trivy da imagem, Dependabot, SBOM CycloneDX |
| A07 Auth Failures | Fora do escopo da aplicação (gateway); sem sessões/senhas locais |
| A08 Software/Data Integrity | Actions versionadas, imagem assinada com Cosign, pipeline como gate de merge |
| A09 Logging Failures | `request_id`, logs de eventos de segurança (bloqueio de injection, saída inválida) |
| A10 SSRF | `LLM_API_URL` restrita a http/https e definida só pelo operador, nunca pelo usuário |

## OWASP Top 10 para aplicações com LLM (2025)

| Item | Como é tratado |
|---|---|
| LLM01 Prompt Injection | Heurística de bloqueio, entrada delimitada por `<incidente>`, prompt de sistema defensivo |
| LLM02 Sensitive Information Disclosure | Redação de PII antes do envio ao provedor; logs sem conteúdo |
| LLM03 Supply Chain | Dependências fixadas, SCA, SBOM, imagem assinada |
| LLM05 Improper Output Handling | `validate_model_output`: enums fechados, tamanho máximo, remoção de `<` e `>` |
| LLM06 Excessive Agency | O modelo **não** executa ações: só devolve sugestões; decisão humana obrigatória (`disclaimer`) |
| LLM07 System Prompt Leakage | Prompt sem segredos; pedido de revelar prompt é bloqueado |
| LLM10 Unbounded Consumption | Limite de payload, de caracteres, rate limiting e timeout do provedor |

> A numeração segue a lista OWASP Top 10 for LLM Applications 2025. Confira a edição vigente em
> https://genai.owasp.org/llm-top-10/ antes de citar no trabalho.

## NIST SSDF (SP 800-218)

| Prática | Evidência |
|---|---|
| PO.3 Ferramentas de suporte | Pipeline de CI/CD com gates automáticos |
| PW.1 Projetar com segurança | Modelo de ameaças |
| PW.4 Reutilizar software seguro | Dependências mínimas + Dependabot |
| PW.7 Revisar/analisar o código | Ruff, Bandit, CodeQL, PR template com checklist |
| PW.8 Testar o código | pytest (22 testes, cobertura ≥ 85 %), ZAP |
| PS.1 Proteger o código | Gitleaks, `.gitignore` de segredos, branch protection (ver README) |
| PS.2 Verificar integridade da release | Cosign + SBOM |
| RV.1 Identificar vulnerabilidades | Scan semanal agendado + Dependabot |
| RV.2 Corrigir vulnerabilidades | Achados corrigidos e registrados em `ANALISE-VULNERABILIDADES.md` |

## LGPD (Lei 13.709/2018)

| Princípio / artigo | Controle |
|---|---|
| Art. 6º, III — Necessidade (minimização) | Redação de PII antes do LLM; logs com hash em vez de conteúdo |
| Art. 6º, VII — Segurança | Controles técnicos desta tabela; container endurecido |
| Art. 6º, VI — Transparência | `disclaimer` informa que o resultado é gerado por IA |
| Art. 20 — Revisão de decisões automatizadas | Decisão final sempre humana; o sistema só sugere |
| Art. 46 — Medidas de segurança | Pipeline DevSecOps, SBOM, scans contínuos |
| Art. 48 — Incidente de segurança | Playbook de vazamento sugere avaliar notificação à ANPD e aos titulares |

## ISO/IEC 27001:2022 (Anexo A — controles selecionados)

| Controle | Evidência |
|---|---|
| A.5.34 Privacidade e proteção de PII | Redação de PII |
| A.8.8 Gestão de vulnerabilidades técnicas | pip-audit, Trivy, Dependabot |
| A.8.9 Gestão de configuração | Dockerfile/compose versionados e escaneados |
| A.8.15 Registro de logs | Logs com `request_id` |
| A.8.25 Ciclo de vida de desenvolvimento seguro | Pipeline DevSecOps completo |
| A.8.28 Codificação segura | Ruff (regras `S` do flake8-bandit), Bandit, CodeQL |
| A.8.29 Testes de segurança | Testes de abuso, ZAP |

## CIS Docker Benchmark (itens aplicados)

> Numeração dos itens conforme o CIS Docker Benchmark; confirme na versão que o professor adotar.

Usuário não-root (4.1) · imagem mínima `slim` multi-stage (4.3) · `HEALTHCHECK` (4.6) · sem segredos na
imagem (4.10) · `read_only` (5.12) · `no-new-privileges` (5.25) · limites de memória/CPU/PIDs (5.10, 5.11, 5.28)
· porta publicada só em loopback (5.13).

## Governança do uso de IA no desenvolvimento

1. Todo prompt usado para gerar código, testes ou documentos é registrado em `prompts/`.
2. Toda saída de IA passa por revisão humana e pelo pipeline antes do merge (checklist no PR template).
3. Nenhum dado pessoal, segredo ou código proprietário é colado em prompts.
4. Saídas de IA no runtime são sugestões; nunca disparam ações automáticas.
