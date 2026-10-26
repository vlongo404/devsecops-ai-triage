# Fase 3 — Pipeline DevSecOps e Docker

## P-PIP-01 — Pipeline GitHub Actions com gates de segurança (v1)

```text
Papel: engenheiro DevSecOps.
Tarefa: crie um workflow GitHub Actions para uma aplicação Python/Flask em Docker com os estágios:
lint+testes → secret scanning → SAST → SCA → lint de Dockerfile/IaC → build + scan de imagem + SBOM
→ DAST → deploy com aprovação manual.
Restrições:
- permissions mínimas (contents: read) e elevadas só por job;
- falhar o build em severidade HIGH/CRITICAL;
- só publicar a imagem depois que todos os gates passarem;
- nenhuma credencial em texto claro: usar secrets e environments;
- fixar versões das actions.
Formato: YAML comentado + tabela "estágio | ferramenta | o que bloqueia".
```

**Validar:** `python -c "import yaml; yaml.safe_load(open('arquivo.yml'))"`; conferir se cada action existe e se a versão é real; executar no GitHub e anexar print.

## P-PIP-02 — Dockerfile endurecido (v1)

```text
Tarefa: escreva um Dockerfile multi-stage para Flask + gunicorn.
Restrições: imagem slim; usuário não-root com UID fixo; sem cache de pip; HEALTHCHECK;
nada de segredos em ENV/ARG; copiar apenas o necessário; gunicorn sem expor versão no cabeçalho Server.
Depois gere o docker-compose.yml com read_only, tmpfs, cap_drop ALL, no-new-privileges, limites de
memória/CPU/PIDs e porta publicada só em 127.0.0.1.
Explique cada linha de endurecimento em uma frase e cite o item do CIS Docker Benchmark se tiver certeza.
```

**Validar:** `hadolint Dockerfile`, `trivy config .`, `docker build`, `docker run` e `curl /health`.
