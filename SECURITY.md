# Política de Segurança

## Reportando uma vulnerabilidade

Não abra uma issue pública. Use **Security → Report a vulnerability** (GitHub Private Vulnerability
Reporting) neste repositório. Prazo alvo de primeira resposta: 5 dias úteis.

## Versões suportadas

| Versão | Suporte |
|---|---|
| 1.x | ✅ |

## Práticas do projeto

- Segredos nunca entram no repositório (Gitleaks + `.gitignore`).
- Toda mudança passa pelo pipeline DevSecOps antes do merge.
- Dependências são monitoradas pelo Dependabot e por scan semanal agendado.
