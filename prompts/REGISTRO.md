# Registro de uso de prompts

Preencha uma linha a cada uso relevante. Isto dá rastreabilidade (NIST SSDF PS.1 / ISO 27001 A.8.25) e
mostra ao professor o que a IA produziu e o que foi aceito, corrigido ou descartado por revisão humana.

| Data | Prompt | Ferramenta / modelo | Resultado | Revisão humana (o que mudou ou foi descartado) |
|---|---|---|---|---|
| 26/10/2026 | Enunciado da atividade (projeto DevSecOps com IA, conformidade, vulnerabilidades, acervo de prompts) | Claude (Anthropic) | Estrutura do repositório, aplicação, pipeline, documentação e slides | Executados localmente: Ruff, Bandit, pip-audit e pytest. Achados corrigidos: Flask 3.1.2 → 3.1.3, B310, cabeçalho `Server`. Pipeline em nuvem ainda não executado |
| | | | | |

> Dica: ao final, anexe aqui um print do histórico do chat e do pipeline verde no GitHub como evidência.
