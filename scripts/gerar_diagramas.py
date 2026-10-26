"""Gera as imagens usadas nos slides e no README (docs/img/*.png).

Uso: pip install pillow && python scripts/gerar_diagramas.py
Os números do gráfico de vulnerabilidades vêm de docs/evidencias/ (antes/depois dos scans).
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent.parent / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)

FONT_DIR = "/usr/share/fonts/truetype/liberation/"
BOLD = FONT_DIR + "LiberationSans-Bold.ttf"
REG = FONT_DIR + "LiberationSans-Regular.ttf"
MONO = FONT_DIR + "LiberationMono-Bold.ttf"

NAVY, PAPER, TEAL, AMBER, SLATE, WHITE = "#12202F", "#F4F1EA", "#1B8F7A", "#E0912B", "#51606F", "#FFFFFF"
W, H = 1600, 900


def f(path, size):
    return ImageFont.truetype(path, size)


def centered(d, box, text, font, fill):
    x0, y0, x1, y1 = box
    lines = text.split("\n")
    heights = [d.textbbox((0, 0), ln, font=font)[3] for ln in lines]
    total = sum(heights) + 8 * (len(lines) - 1)
    y = y0 + (y1 - y0 - total) / 2
    for ln, h in zip(lines, heights, strict=True):
        w = d.textlength(ln, font=font)
        d.text((x0 + (x1 - x0 - w) / 2, y), ln, font=font, fill=fill)
        y += h + 8


def arrow(d, p0, p1, color=SLATE, width=5):
    d.line([p0, p1], fill=color, width=width)
    (x0, y0), (x1, y1) = p0, p1
    if abs(x1 - x0) >= abs(y1 - y0):
        s = 1 if x1 > x0 else -1
        d.polygon([(x1, y1), (x1 - s * 22, y1 - 13), (x1 - s * 22, y1 + 13)], fill=color)
    else:
        s = 1 if y1 > y0 else -1
        d.polygon([(x1, y1), (x1 - 13, y1 - s * 22), (x1 + 13, y1 - s * 22)], fill=color)


def box(d, xy, fill, outline=None, r=22, width=4):
    d.rounded_rectangle(xy, radius=r, fill=fill, outline=outline, width=width)


# ---------------------------------------------------------------- arquitetura
def arquitetura():
    im = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(im)
    d.text((60, 40), "Arquitetura: IA com controles em cada fronteira", font=f(BOLD, 44), fill=NAVY)

    # Container endurecido
    box(d, (470, 150, 1130, 790), "#E6F1EE", TEAL, width=5)
    titulo = "CONTAINER ENDURECIDO (não-root, read-only, cap_drop ALL)"
    d.text((495, 162), titulo, font=f(MONO, 19), fill=TEAL)

    box(d, (60, 400, 330, 540), NAVY)
    centered(d, (60, 400, 330, 540), "Analista /\ncliente", f(BOLD, 32), WHITE)
    box(d, (1250, 540, 1540, 760), NAVY)
    centered(d, (1250, 540, 1540, 760), "Provedor LLM\n(mock ou API)", f(BOLD, 30), WHITE)

    steps = [
        ("1  Valida entrada (tipo, 2000 car.)", 215),
        ("2  Bloqueia prompt injection", 330),
        ("3  Redige PII (LGPD)", 445),
        ("4  Prompt de sistema versionado", 560),
        ("5  Valida a saída do modelo", 675),
    ]
    for text, y in steps:
        box(d, (505, y, 1095, y + 85), WHITE, TEAL, r=16, width=3)
        centered(d, (505, y, 1095, y + 85), text, f(BOLD, 27), NAVY)
    for (_, y) in steps[:-1]:
        arrow(d, (800, y + 85), (800, y + 115), TEAL, 4)

    box(d, (350, 340, 450, 400), AMBER, r=12)
    centered(d, (350, 340, 450, 400), "TLS+auth", f(BOLD, 18), NAVY)
    arrow(d, (330, 470), (500, 470), SLATE)
    arrow(d, (1095, 590), (1245, 590), SLATE)
    arrow(d, (1245, 717), (1100, 717), SLATE)
    d.text((1142, 556), "prompt", font=f(REG, 22), fill=SLATE)
    d.text((1142, 684), "JSON", font=f(REG, 22), fill=SLATE)
    rodape = "Decisão final sempre humana. A IA só sugere (OWASP LLM06)."
    d.text((60, 830), rodape, font=f(REG, 26), fill=SLATE)
    im.save(OUT / "arquitetura.png")


# ------------------------------------------------------------------- pipeline
def pipeline():
    im = Image.new("RGB", (W, H), NAVY)
    d = ImageDraw.Draw(im)
    d.text((60, 40), "Pipeline DevSecOps: 8 estágios, cada um é um gate", font=f(BOLD, 44), fill=PAPER)
    stages = [
        ("1", "Lint + testes", "Ruff, pytest\ncobertura ≥ 85%"),
        ("2", "Segredos", "Gitleaks"),
        ("3", "SAST", "Bandit, CodeQL"),
        ("4", "SCA", "pip-audit"),
        ("5", "Docker / IaC", "Hadolint\nTrivy config"),
        ("6", "Imagem", "Trivy, Syft SBOM\nCosign"),
        ("7", "DAST", "OWASP ZAP"),
        ("8", "Deploy", "aprovação manual\nenvironment"),
    ]
    bw, bh, gap = 330, 250, 62
    for i, (n, title, sub) in enumerate(stages):
        row, col = divmod(i, 4)
        x0 = 60 + col * (bw + gap)
        y0 = 170 + row * 340
        accent = AMBER if i == 7 else TEAL
        box(d, (x0, y0, x0 + bw, y0 + bh), "#1B3047", accent, width=4)
        d.ellipse((x0 + 20, y0 + 20, x0 + 78, y0 + 78), fill=accent)
        centered(d, (x0 + 20, y0 + 20, x0 + 78, y0 + 78), n, f(BOLD, 34), NAVY)
        d.text((x0 + 95, y0 + 28), title, font=f(BOLD, 34), fill=PAPER)
        d.multiline_text((x0 + 28, y0 + 120), sub, font=f(MONO, 25), fill="#BFD8D5", spacing=10)
        if col < 3:
            arrow(d, (x0 + bw + 8, y0 + bh // 2), (x0 + bw + gap - 8, y0 + bh // 2), PAPER)
    xa, xb = 60 + 3 * (bw + gap) + bw // 2, 60 + bw // 2
    d.line([(xa, 170 + 250 + 6), (xa, 170 + 295), (xb, 170 + 295)], fill=PAPER, width=5)
    arrow(d, (xb, 170 + 295), (xb, 170 + 340 - 8), PAPER)
    d.text((60, 830), "Qualquer falha bloqueia o merge e o push da imagem.", font=f(REG, 28), fill="#BFD8D5")
    im.save(OUT / "pipeline.png")


# -------------------------------------------------------------- vulnerabilidades
def vulnerabilidades():
    im = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(im)
    d.text((60, 40), "Achados reais: antes e depois da correção", font=f(BOLD, 44), fill=NAVY)
    rows = [
        ("pip-audit: vulnerabilidades em dependências", 1, 0),
        ("Bandit: achados de severidade média (B310)", 1, 0),
        ("Ruff: pendências de lint", 4, 0),
    ]
    x_label, x_bar, unit = 60, 300, 220
    y = 200
    for label, antes, depois in rows:
        d.text((x_label, y), label, font=f(BOLD, 28), fill=NAVY)
        d.text((x_label, y + 52), "antes", font=f(REG, 24), fill=SLATE)
        d.rounded_rectangle((x_bar - 100, y + 48, x_bar - 100 + max(antes * unit, 8), y + 90), 8, fill=AMBER)
        d.text((x_bar - 100 + antes * unit + 16, y + 50), str(antes), font=f(BOLD, 30), fill=NAVY)
        d.text((x_label, y + 112), "depois", font=f(REG, 24), fill=SLATE)
        d.rounded_rectangle((x_bar - 100, y + 108, x_bar - 100 + 8, y + 150), 4, fill=TEAL)
        d.text((x_bar - 100 + 24, y + 110), str(depois), font=f(BOLD, 30), fill=TEAL)
        y += 200
    d.text((60, 800), "Testes: 22 passando, cobertura 86,7%. Flask 3.1.2 → 3.1.3 (PYSEC-2026-2151).",
           font=f(REG, 28), fill=SLATE)
    im.save(OUT / "vulnerabilidades.png")


if __name__ == "__main__":
    arquitetura()
    pipeline()
    vulnerabilidades()
    print("ok:", sorted(p.name for p in OUT.glob("*.png")))
