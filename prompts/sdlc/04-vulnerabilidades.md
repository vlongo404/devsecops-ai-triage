# Fase 4 — Análise de vulnerabilidades

## P-VUL-01 — Triagem de achados de scanners (v1)

```text
Papel: analista de vulnerabilidades.
Contexto: aplicação Flask em container, exposta apenas via reverse proxy, sem dados sensíveis persistidos.
Tarefa: priorize os achados abaixo (saída de Bandit / pip-audit / Trivy).
Para cada achado informe: é falso positivo? (justifique), explorabilidade neste contexto, severidade
ajustada ao contexto, correção recomendada e como verificar que foi corrigido.
Restrições: não invente CVEs nem versões corrigidas; se faltar informação, diga o que precisa.
Formato: tabela + lista de ações ordenada por prioridade.
[cole a saída dos scanners — sem segredos]
```

**Validar:** confirmar a versão corrigida no advisory oficial; reexecutar o scanner depois da correção e guardar a evidência antes/depois em `docs/evidencias/`.

## P-VUL-02 — Explicar um achado para a equipe (v1)

```text
Explique este achado em linguagem simples para um desenvolvedor júnior: o que é, como um atacante
exploraria na nossa aplicação, como corrigir e como escrever um teste que impeça a regressão.
[cole o achado]
```

## P-VUL-03 — Texto de risco aceito (v1)

```text
Redija a justificativa de risco residual aceito para o achado abaixo, com: descrição, motivo da aceitação,
controles compensatórios, responsável e data de reavaliação. Tom objetivo, sem minimizar o risco.
```
