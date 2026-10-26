"""Provedores de LLM plugáveis.

- ``mock``: classificador por regras, determinístico. Padrão — permite rodar
  testes e pipeline CI sem chave de API e sem custo.
- ``openai_compatible``: qualquer endpoint compatível com /v1/chat/completions
  (OpenAI, Azure OpenAI, Ollama, vLLM, LiteLLM...). A chave vem de variável
  de ambiente / secret, NUNCA do código (OWASP A02, gitleaks no pipeline).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from .security import InvalidModelOutput, validate_model_output

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts" / "runtime"


def load_system_prompt() -> str:
    """O prompt de sistema é versionado no GitHub (acervo de prompts)."""
    return (PROMPTS_DIR / "triage_system.md").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
class MockProvider:
    name = "mock"

    _RULES = (
        (("ransomware", "criptograd", "resgate", "encrypted files"), "malware", "critica",
         "Indícios de ransomware com criptografia de arquivos."),
        (("phishing", "link suspeito", "senha", "credencial", "fake login"), "phishing", "media",
         "Possível tentativa de phishing / roubo de credenciais."),
        (("vazamento", "leak", "exfiltra", "dados expostos", "bucket publico", "bucket público"),
         "vazamento_de_dados", "alta", "Possível exposição ou exfiltração de dados."),
        (("ddos", "negação de serviço", "negacao de servico", "flood", "indisponível", "fora do ar"),
         "negacao_de_servico", "alta", "Padrão compatível com negação de serviço."),
        (("login", "acesso não autorizado", "acesso nao autorizado", "brute", "força bruta",
          "forca bruta", "privilégio", "privilegio"),
         "acesso_indevido", "alta", "Indícios de acesso indevido ou força bruta."),
        (("cve-", "vulnerabilidade", "patch", "sql injection", "xss", "rce"),
         "vulnerabilidade", "media", "Vulnerabilidade reportada que requer avaliação."),
    )

    _ACTIONS = {
        "malware": ["Isolar o host da rede", "Preservar evidências (memória e disco)",
                    "Acionar o plano de resposta a incidentes", "Restaurar de backup íntegro"],
        "phishing": ["Redefinir credenciais afetadas", "Bloquear URL/domínio no proxy",
                     "Ativar MFA", "Avisar usuários sobre a campanha"],
        "vazamento_de_dados": ["Conter a exposição", "Avaliar dados pessoais envolvidos (LGPD)",
                               "Avaliar notificação à ANPD e aos titulares", "Revisar permissões"],
        "negacao_de_servico": ["Ativar mitigação de DDoS/WAF", "Aplicar rate limiting",
                               "Escalar capacidade", "Registrar IPs de origem"],
        "acesso_indevido": ["Revogar sessões e tokens", "Bloquear IP de origem",
                            "Revisar logs de autenticação", "Exigir MFA"],
        "vulnerabilidade": ["Classificar pelo CVSS", "Aplicar patch ou mitigação",
                            "Reexecutar o scan de vulnerabilidades"],
        "outro": ["Coletar mais informações", "Encaminhar ao analista de plantão"],
    }

    def classify(self, text: str, system_prompt: str) -> dict:
        lowered = text.lower()
        for keywords, category, severity, summary in self._RULES:  # noqa: B007
            if any(k in lowered for k in keywords):
                break
        else:
            category, severity, summary = "outro", "baixa", "Relato sem padrão conhecido."
        return validate_model_output(
            {
                "severity": severity,
                "category": category,
                "summary": summary,
                "recommended_actions": self._ACTIONS[category],
            }
        )


# --------------------------------------------------------------------------
class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self) -> None:
        self.url = os.environ["LLM_API_URL"]
        self.key = os.environ["LLM_API_KEY"]
        self.model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.timeout = float(os.environ.get("LLM_TIMEOUT", "15"))
        # Evita SSRF / esquemas inesperados (file://, ftp://...)
        parsed = urlparse(self.url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValueError("LLM_API_URL inválida")

    def classify(self, text: str, system_prompt: str) -> dict:
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"<incidente>\n{text}\n</incidente>"},
                ],
            }
        ).encode()
        req = urllib.request.Request(  # noqa: S310 - esquema validado no __init__
            self.url,
            data=body,
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            # Esquema http(s) validado no __init__ (mitiga B310 / CWE-22)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310
                payload = json.load(resp)
            content = payload["choices"][0]["message"]["content"]
            return validate_model_output(json.loads(content))
        except (urllib.error.URLError, KeyError, IndexError, json.JSONDecodeError) as exc:
            raise InvalidModelOutput("falha ao obter resposta válida do provedor") from exc


def get_provider():
    name = os.environ.get("LLM_PROVIDER", "mock").lower()
    if name == "openai_compatible":
        return OpenAICompatibleProvider()
    return MockProvider()
