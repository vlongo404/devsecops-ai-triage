# Fase 1 — Requisitos e ameaças

## P-REQ-01 — Requisitos de segurança (v1)

**Objetivo:** derivar requisitos de segurança verificáveis a partir da descrição da aplicação.

```text
Papel: você é um arquiteto de segurança de aplicações.
Contexto: API Flask que recebe relatos de incidentes de segurança em texto livre, envia a um LLM
para classificar severidade e categoria e devolve sugestões. Será executada em containers Docker,
em qualquer cloud. Deve respeitar a LGPD.
Tarefa: liste requisitos de segurança funcionais e não funcionais.
Restrições: cada requisito deve ser testável (indique como testar), numerado (RS-01...) e mapeado
para OWASP ASVS ou OWASP Top 10 for LLM Applications. Não invente números de controle: se não tiver
certeza do ID, escreva "verificar".
Formato: tabela Markdown com colunas ID | Requisito | Como testar | Referência.
```

**Validar:** requisitos testáveis? Referências conferidas na fonte oficial? Algum requisito genérico demais?

## P-REQ-02 — Modelagem de ameaças STRIDE (v1)

```text
Papel: especialista em threat modeling.
Contexto: [cole a descrição da arquitetura SEM segredos: cliente → API → provedor LLM, logs, container].
Tarefa: aplique STRIDE em cada fronteira de confiança e inclua as ameaças específicas de LLM
(prompt injection, vazamento de dados no prompt, saída insegura, consumo ilimitado).
Restrições: para cada ameaça dê probabilidade e impacto (baixo/médio/alto), o controle proposto
e onde ele seria implementado no código ou no pipeline.
Formato: tabela Markdown.
```

**Validar:** cada ameaça tem um controle implementável? Há ameaça sem dono ou sem teste?

## P-REQ-03 — Casos de abuso (v1)

```text
Tarefa: para a rota POST /triage escreva 15 casos de abuso (entradas maliciosas ou malformadas)
com a resposta HTTP esperada. Inclua prompt injection em português e inglês, payloads gigantes,
JSON inválido, tipos errados, Unicode estranho e tentativa de exfiltrar o prompt de sistema.
Formato: tabela com Entrada | Resposta esperada | Controle que bloqueia.
```
