# Acervo de Prompts

Repositório versionado dos prompts usados para **construir** e **operar** este projeto com IA. Cada prompt é
tratado como código: tem ID, versão, objetivo, critério de validação e passa por revisão em Pull Request.

## Estrutura

| Pasta/arquivo | Conteúdo |
|---|---|
| [`TEMPLATE.md`](TEMPLATE.md) | Modelo para registrar um novo prompt |
| [`REGISTRO.md`](REGISTRO.md) | Diário de uso: qual prompt, qual ferramenta/modelo, quando, e o que foi aceito ou rejeitado |
| [`sdlc/01-requisitos-e-ameacas.md`](sdlc/01-requisitos-e-ameacas.md) | Requisitos de segurança e modelagem de ameaças |
| [`sdlc/02-codigo-e-testes.md`](sdlc/02-codigo-e-testes.md) | Geração e revisão de código seguro, testes de abuso |
| [`sdlc/03-pipeline-e-docker.md`](sdlc/03-pipeline-e-docker.md) | Pipeline DevSecOps, Dockerfile e compose endurecidos |
| [`sdlc/04-vulnerabilidades.md`](sdlc/04-vulnerabilidades.md) | Triagem e priorização de achados de scanners |
| [`sdlc/05-conformidade.md`](sdlc/05-conformidade.md) | Mapeamento para OWASP, NIST SSDF, LGPD, ISO 27001 |
| [`sdlc/06-documentacao.md`](sdlc/06-documentacao.md) | README, relatório e slides |
| [`runtime/triage_system.md`](runtime/triage_system.md) | Prompt de sistema usado **pela aplicação em produção** (carregado em tempo de execução) |

## Regras de governança

1. **Nenhum dado sensível em prompts**: sem segredos, chaves, CPFs, logs reais de clientes ou código proprietário.
2. **Saída de IA é rascunho**: só entra no repositório depois de revisão humana e de passar no pipeline.
3. **Prompts de runtime são código de produção**: mudanças exigem Pull Request e testes (`tests/`).
4. **Rastreabilidade**: toda geração relevante é anotada em `REGISTRO.md`.
5. **Prompts são dados não confiáveis quando misturam entrada de usuário**: usar delimitadores e nunca
   concatenar instruções com conteúdo externo sem marcação (OWASP LLM01).

## Convenção de IDs

`P-<fase>-<número>` — ex.: `P-COD-02`. Fases: `REQ`, `COD`, `PIP`, `VUL`, `CNF`, `DOC`. Versão no formato `v1`, `v2`.

## Dicas para escrever bons prompts de segurança

- Dê **papel, contexto, tarefa, restrições e formato de saída**.
- Peça **exemplos de abuso**, não só do caminho feliz.
- Peça que o modelo **diga o que não sabe** em vez de inventar CVEs, versões ou números de controle.
- Sempre **verifique** CVEs e IDs de controle na fonte oficial (NVD, OWASP, ISO) antes de citar.
