# Fase 5 — Conformidade

## P-CNF-01 — Matriz de conformidade (v1)

```text
Papel: especialista em GRC.
Tarefa: mapeie os controles implementados neste projeto [cole a lista de controles e arquivos] para
OWASP Top 10, OWASP Top 10 for LLM Applications, NIST SSDF, LGPD e ISO/IEC 27001:2022 Anexo A.
Restrições: cite apenas IDs de controle de que tenha certeza; quando não tiver, escreva "verificar".
Para cada linha indique a evidência (arquivo ou etapa do pipeline). Não afirme "conformidade total"
nem certificação — trata-se de alinhamento.
Formato: uma tabela por framework.
```

**Validar:** conferir cada ID na norma oficial; remover qualquer afirmação sem evidência no repositório.

## P-CNF-02 — Avaliação LGPD do fluxo de dados (v1)

```text
Descreva o fluxo de dados pessoais possíveis nesta aplicação (entrada de texto livre → redação → LLM →
logs). Para cada etapa: dado tratado, base legal provável, risco, medida técnica. Aponte lacunas
(por exemplo: nomes próprios não são redigidos por regex). Não é parecer jurídico; indique o que o
encarregado (DPO) deveria validar.
```

## P-CNF-03 — Checklist de governança do uso de IA (v1)

```text
Crie um checklist de governança para o uso de IA generativa no desenvolvimento: dados proibidos em prompts,
revisão humana, registro de prompts, licenças, avaliação de provedores e tratamento de alucinações.
```
