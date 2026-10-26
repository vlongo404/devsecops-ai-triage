"""Controles de segurança da aplicação.

Mapeamento (ver docs/CONFORMIDADE.md):
- Redação de PII ............ LGPD art. 6º (minimização) / ISO 27001 A.5.34
- Detecção de prompt injection OWASP LLM01 (Prompt Injection)
- Validação de saída do LLM . OWASP LLM05 (Improper Output Handling)
- Rate limiting ............. OWASP LLM10 (Unbounded Consumption) / API4:2023
- Cabeçalhos HTTP ........... OWASP ASVS V14
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict

# --------------------------------------------------------------------------
# 1. Redação de dados pessoais (LGPD) — executada ANTES de enviar ao LLM
# --------------------------------------------------------------------------
_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("CPF", re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")),
    ("CNPJ", re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")),
    ("TELEFONE", re.compile(r"(?:\+55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b")),
    ("CARTAO", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
]


def redact_pii(text: str) -> tuple[str, int]:
    """Substitui dados pessoais por marcadores. Retorna (texto, qtd_redacoes)."""
    total = 0
    for label, pattern in _PII_PATTERNS:
        text, n = pattern.subn(f"[{label}_REDACTED]", text)
        total += n
    return text, total


# --------------------------------------------------------------------------
# 2. Heurística contra prompt injection (OWASP LLM01)
# --------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignor(e|ar|a)\s+(all|todas|tudo|as|previous|anteriores|instru)",
        r"disregard\s+(the\s+)?(above|previous|system)",
        r"(reveal|show|print|mostre|revele)\s+(your|o|seu)?\s*(system\s*prompt|prompt\s+de\s+sistema|instru)",
        r"you\s+are\s+now\s+",
        r"voc[eê]\s+agora\s+[eé]\s+",
        r"\bDAN\b|developer\s+mode|modo\s+desenvolvedor",
        r"<\s*/?\s*(system|assistant)\s*>",
    )
]


def looks_like_prompt_injection(text: str) -> bool:
    return any(p.search(text) for p in _INJECTION_PATTERNS)


# --------------------------------------------------------------------------
# 3. Validação estrita da saída do modelo (OWASP LLM05)
# --------------------------------------------------------------------------
ALLOWED_SEVERITY = ("baixa", "media", "alta", "critica")
ALLOWED_CATEGORY = (
    "phishing",
    "malware",
    "acesso_indevido",
    "vazamento_de_dados",
    "negacao_de_servico",
    "vulnerabilidade",
    "outro",
)
_MAX_ACTIONS = 6
_MAX_FIELD = 300
_HTML = re.compile(r"[<>]")


def _clean(value: object) -> str:
    s = str(value)[:_MAX_FIELD]
    return _HTML.sub("", s).strip()


class InvalidModelOutput(ValueError):
    """O modelo devolveu algo fora do contrato."""


def validate_model_output(data: object) -> dict:
    """Garante que a saída do LLM respeita o contrato; nunca confia no modelo."""
    if not isinstance(data, dict):
        raise InvalidModelOutput("saída não é um objeto JSON")
    severity = data.get("severity")
    category = data.get("category")
    if severity not in ALLOWED_SEVERITY:
        raise InvalidModelOutput("severity fora do domínio permitido")
    if category not in ALLOWED_CATEGORY:
        raise InvalidModelOutput("category fora do domínio permitido")
    actions = data.get("recommended_actions")
    if not isinstance(actions, list) or not actions:
        raise InvalidModelOutput("recommended_actions inválido")
    return {
        "severity": severity,
        "category": category,
        "summary": _clean(data.get("summary", "")),
        "recommended_actions": [_clean(a) for a in actions[:_MAX_ACTIONS]],
    }


# --------------------------------------------------------------------------
# 4. Rate limiting (token bucket em memória, por IP)
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = defaultdict(
            lambda: (float(capacity), time.monotonic())
        )
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets[key]
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True


# --------------------------------------------------------------------------
# 5. Cabeçalhos de segurança HTTP
# --------------------------------------------------------------------------
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}
