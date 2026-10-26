# Fase 2 — Código e testes

## P-COD-01 — Geração de código seguro (v1)

```text
Papel: engenheiro Python sênior com foco em segurança.
Tarefa: implemente a rota POST /triage em Flask.
Requisitos: [cole os RS-xx aplicáveis].
Restrições:
- valide tipo e tamanho da entrada; rejeite o resto com 400;
- nunca confie na saída do LLM: valide contra enums fechados;
- não registre o conteúdo do incidente em logs (apenas hash e request_id);
- sem segredos no código; tudo por variáveis de ambiente;
- dependências mínimas e fixadas;
- comente apenas o porquê das decisões de segurança.
Formato: código completo + lista de decisões de segurança + o que ficou de fora.
```

**Validar:** rodar `ruff`, `bandit`, `pytest`; ler o código linha a linha; procurar dependências inventadas.

## P-COD-02 — Revisão de código com foco em segurança (v1)

```text
Papel: revisor de segurança (AppSec).
Tarefa: revise o código abaixo procurando: injeção, SSRF, desserialização, vazamento de dados,
tratamento de erro que expõe detalhes, race conditions e problemas específicos de LLM
(prompt injection, saída insegura, consumo ilimitado).
Formato: lista por severidade (alta/média/baixa) com: trecho, risco, correção sugerida.
Se não encontrar problema numa categoria, diga "nada encontrado" — não invente achados.
[cole o código]
```

**Validar:** reproduzir cada achado antes de corrigir; descartar falsos positivos explicando o porquê.

## P-COD-03 — Testes de abuso com pytest (v1)

```text
Tarefa: escreva testes pytest para a API Flask abaixo cobrindo caminho feliz E casos de abuso:
body não-JSON, campo ausente, tipo errado, texto vazio, texto acima do limite, payload acima de
MAX_CONTENT_LENGTH, prompt injection (PT e EN), PII na entrada, saída inválida do provedor, rate limit.
Restrições: use o test client do Flask; use um provedor falso (stub) em vez de rede real;
um comportamento por teste; nomes descritivos.
```

**Validar:** os testes falham se o controle for removido? (Teste de mutação manual: comente o controle e rode.)
