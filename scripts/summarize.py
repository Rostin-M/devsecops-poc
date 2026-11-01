#!/usr/bin/env python3
"""Resume los resultados de los escáneres, calcula métricas y aplica el quality gate.

Uso:
    python3 scripts/summarize.py results/vulnerable-app --target vulnerable-app
    python3 scripts/summarize.py results/fixed-app --target fixed-app --fail-on-findings

Lee los JSON que dejan Gitleaks, Semgrep, pip-audit, Trivy y OWASP ZAP (los que existan).
Si existe la variable GITHUB_STEP_SUMMARY, escribe ahí la tabla en Markdown.
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path


def load(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def read_timings(out: Path) -> dict:
    tiempos = {}
    f = out / "timings.txt"
    if f.exists():
        for linea in f.read_text().splitlines():
            partes = linea.split()
            if len(partes) == 3:
                tiempos[partes[0]] = float(partes[1])
    return tiempos


def gitleaks(out: Path):
    data = load(out / "gitleaks.json")
    if data is None:
        return None
    return {"total": len(data), "detalle": dict(Counter(h["RuleID"] for h in data))}


def semgrep(out: Path):
    data = load(out / "semgrep.json")
    if data is None:
        return None
    sev = Counter(r["extra"]["severity"] for r in data.get("results", []))
    reglas = Counter(r["check_id"].split(".")[-1] for r in data.get("results", []))
    return {
        "total": sum(sev.values()),
        "ERROR": sev.get("ERROR", 0),
        "WARNING": sev.get("WARNING", 0),
        "detalle": dict(reglas),
    }


def pip_audit(out: Path):
    data = load(out / "pip-audit.json")
    if data is None:
        return None
    vulns = [v for d in data.get("dependencies", []) for v in d.get("vulns", [])]
    paquetes = sum(1 for d in data.get("dependencies", []) if d.get("vulns"))
    return {"total": len(vulns), "paquetes_afectados": paquetes}


def trivy_config(out: Path):
    data = load(out / "trivy-config.json")
    if data is None:
        return None
    sev = Counter()
    for res in data.get("Results", []):
        for m in res.get("Misconfigurations", []) or []:
            sev[m["Severity"]] += 1
    return {"total": sum(sev.values()), "HIGH+CRITICAL": sev["HIGH"] + sev["CRITICAL"], "detalle": dict(sev)}


def trivy_image(out: Path):
    data = load(out / "trivy-image.json")
    if data is None:
        return None
    sev = Counter()
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            sev[v["Severity"]] += 1
    return {"total": sum(sev.values()), "HIGH+CRITICAL": sev["HIGH"] + sev["CRITICAL"], "detalle": dict(sev)}


def zap(out: Path):
    data = load(out / "zap.json")
    if data is None:
        return None
    niveles = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
    cont = Counter()
    for site in data.get("site", []):
        for alerta in site.get("alerts", []):
            cont[niveles.get(str(alerta.get("riskcode")), "Info")] += 1
    return {"total": sum(cont.values()), "High": cont["High"], "Medium": cont["Medium"], "detalle": dict(cont)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path, help="carpeta con los resultados")
    ap.add_argument("--target", default="app")
    ap.add_argument("--fail-on-findings", action="store_true", help="salir con 1 si el quality gate falla")
    ap.add_argument(
        "--require",
        default="",
        help="escáneres (separados por coma) que deben haber dejado reporte; si falta alguno el gate rechaza",
    )
    args = ap.parse_args()

    t = read_timings(args.out)
    r = {
        "gitleaks": gitleaks(args.out),
        "semgrep": semgrep(args.out),
        "pip-audit": pip_audit(args.out),
        "trivy-config": trivy_config(args.out),
        "trivy-image": trivy_image(args.out),
        "zap": zap(args.out),
    }

    # Quality gate: qué hallazgos detienen el pipeline
    motivos = []
    if r["gitleaks"] and r["gitleaks"]["total"] > 0:
        motivos.append(f"{r['gitleaks']['total']} secreto(s) expuesto(s)")
    if r["semgrep"] and r["semgrep"]["ERROR"] > 0:
        motivos.append(f"{r['semgrep']['ERROR']} hallazgo(s) SAST de severidad ERROR")
    if r["pip-audit"] and r["pip-audit"]["total"] > 0:
        motivos.append(f"{r['pip-audit']['total']} vulnerabilidad(es) en dependencias")
    if r["trivy-config"] and r["trivy-config"]["HIGH+CRITICAL"] > 0:
        motivos.append(f"{r['trivy-config']['HIGH+CRITICAL']} misconfiguración(es) HIGH/CRITICAL")
    if r["trivy-image"] and r["trivy-image"]["HIGH+CRITICAL"] > 0:
        motivos.append(f"{r['trivy-image']['HIGH+CRITICAL']} CVE(s) HIGH/CRITICAL en la imagen")
    if r["zap"] and r["zap"]["High"] > 0:
        motivos.append(f"{r['zap']['High']} alerta(s) High en DAST")
    # Falla cerrada: si un escáner no dejó reporte, no hay evidencia y el gate no puede aprobar.
    faltantes = [n for n in args.require.split(",") if n and r.get(n) is None]
    for n in faltantes:
        motivos.append(f"sin reporte de {n} (el escáner falló o no corrió)")
    gate_ok = not motivos

    def celda(nombre, valor, extra=""):
        seg = f"{t[nombre]:.1f} s" if nombre in t else "n/d"
        return f"| {nombre} | {valor} | {extra or '-'} | {seg} |"

    filas = []
    if r["gitleaks"] is not None:
        filas.append(celda("gitleaks", r["gitleaks"]["total"], str(r["gitleaks"]["detalle"])))
    if r["semgrep"] is not None:
        filas.append(celda("semgrep", r["semgrep"]["total"], f"ERROR {r['semgrep']['ERROR']} / WARNING {r['semgrep']['WARNING']}"))
    if r["pip-audit"] is not None:
        filas.append(celda("pip-audit", r["pip-audit"]["total"], f"{r['pip-audit']['paquetes_afectados']} paquete(s) afectado(s)"))
    if r["trivy-config"] is not None:
        filas.append(celda("trivy-config", r["trivy-config"]["total"], str(r["trivy-config"]["detalle"])))
    if r["trivy-image"] is not None:
        filas.append(celda("trivy-image", r["trivy-image"]["total"], str(r["trivy-image"]["detalle"])))
    if r["zap"] is not None:
        filas.append(celda("zap", r["zap"]["total"], str(r["zap"]["detalle"])))
    for n in faltantes:
        filas.append(celda(n, "sin reporte", "el escáner falló o no corrió"))

    md = [
        f"### Resultados de seguridad: `{args.target}`",
        "",
        "| Herramienta | Hallazgos | Detalle | Tiempo |",
        "| --- | --- | --- | --- |",
        *filas,
        "",
        f"**Quality gate: {'APROBADO' if gate_ok else 'RECHAZADO'}**"
        + ("" if gate_ok else " — " + "; ".join(motivos)),
    ]
    texto = "\n".join(md)
    print(texto)

    (args.out / "metrics.json").write_text(
        json.dumps({"target": args.target, "tiempos_s": t, "resultados": r, "gate_ok": gate_ok, "motivos": motivos}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen:
        with open(resumen, "a", encoding="utf-8") as f:
            f.write(texto + "\n")

    return 1 if (args.fail_on_findings and not gate_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
