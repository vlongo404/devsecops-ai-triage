# syntax=docker/dockerfile:1
# ---- Estágio 1: build das dependências ------------------------------------
FROM python:3.13-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# ---- Estágio 2: imagem final mínima, sem root ------------------------------
FROM python:3.13-slim
LABEL org.opencontainers.image.title="devsecops-ai-triage" \
      org.opencontainers.image.description="Triagem de incidentes com IA - projeto DevSecOps" \
      org.opencontainers.image.source="https://github.com/vlongo404/devsecops-ai-triage"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000
# Aplica correções de segurança do sistema e remove o pip/setuptools da imagem final
# (não são necessários em execução e reduzem a superfície de ataque).
# hadolint ignore=DL3005,DL3008
RUN apt-get update \
 && apt-get -y --no-install-recommends upgrade \
 && rm -rf /var/lib/apt/lists/* \
 && pip uninstall -y pip setuptools wheel
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app

WORKDIR /srv
COPY --from=builder /install /usr/local
COPY app ./app
COPY gunicorn.conf.py ./gunicorn.conf.py
COPY prompts/runtime ./prompts/runtime

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:create_app()"]
