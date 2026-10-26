"""API Flask de triagem de incidentes de segurança assistida por IA."""

from __future__ import annotations

import hashlib
import logging
import os
import uuid

from flask import Flask, jsonify, request

from . import __version__
from .llm import get_provider, load_system_prompt
from .security import (
    SECURITY_HEADERS,
    InvalidModelOutput,
    RateLimiter,
    looks_like_prompt_injection,
    redact_pii,
)

MAX_INPUT_CHARS = 2000

log = logging.getLogger("triage")


def create_app(provider=None, limiter: RateLimiter | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024  # 8 KB: limita payload (LLM10)
    app.json.sort_keys = False

    provider = provider or get_provider()
    limiter = limiter or RateLimiter(
        capacity=int(os.environ.get("RATE_LIMIT_BURST", "10")),
        refill_per_sec=float(os.environ.get("RATE_LIMIT_PER_SEC", "1")),
    )
    system_prompt = load_system_prompt()

    @app.after_request
    def _headers(resp):
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        resp.headers.pop("Server", None)
        return resp

    @app.get("/health")
    def health():
        return jsonify(status="ok", version=__version__, provider=provider.name)

    @app.post("/triage")
    def triage():
        if not limiter.allow(request.remote_addr or "unknown"):
            return jsonify(error="rate_limit_exceeded"), 429

        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            return jsonify(error="body deve ser JSON com o campo 'text' (string)"), 400

        text = data["text"].strip()
        if not text or len(text) > MAX_INPUT_CHARS:
            return jsonify(error=f"'text' deve ter entre 1 e {MAX_INPUT_CHARS} caracteres"), 400

        request_id = str(uuid.uuid4())

        if looks_like_prompt_injection(text):
            # Registra apenas o hash: nunca grava o conteúdo (LGPD / minimização)
            log.warning("prompt_injection_blocked id=%s sha256=%s", request_id,
                        hashlib.sha256(text.encode()).hexdigest()[:16])
            return jsonify(error="entrada rejeitada pela política de segurança",
                           request_id=request_id), 422

        safe_text, redactions = redact_pii(text)

        try:
            result = provider.classify(safe_text, system_prompt)
        except InvalidModelOutput:
            log.error("model_output_invalid id=%s provider=%s", request_id, provider.name)
            return jsonify(error="falha ao processar a triagem", request_id=request_id), 502

        log.info("triage_ok id=%s provider=%s severity=%s pii_redactions=%d",
                 request_id, provider.name, result["severity"], redactions)
        return jsonify(
            request_id=request_id,
            provider=provider.name,
            pii_redactions=redactions,
            **result,
            disclaimer="Sugestão gerada por IA. Requer validação de um analista humano.",
        )

    @app.errorhandler(413)
    def _too_large(_):
        return jsonify(error="payload muito grande"), 413

    @app.errorhandler(404)
    def _not_found(_):
        return jsonify(error="não encontrado"), 404

    return app


if __name__ == "__main__":  # pragma: no cover - uso local; em produção usa gunicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
