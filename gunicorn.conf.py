"""Configuração do Gunicorn.

Oculta a identificação do servidor no cabeçalho `Server` (reduz fingerprinting,
OWASP ASVS V14.3.2). Precisa rodar antes de gunicorn.http.wsgi ser importado.
"""
import gunicorn

gunicorn.SERVER = "webserver"
gunicorn.SERVER_SOFTWARE = "webserver"

bind = "0.0.0.0:8000"
workers = 2
accesslog = "-"
