# PoC DevSecOps: seguridad automática en el pipeline CI/CD

Prueba de concepto para el módulo de Arquitectura de Software (Universidad de Medellín).
Componente explorado: **ciberseguridad en el pipeline de integración continua (DevSecOps)**.

La idea: dos versiones de la misma mini tienda en Flask pasan por el mismo pipeline.
`vulnerable-app/` tiene fallas a propósito y el pipeline debe **rechazarla**.
`fixed-app/` tiene las fallas corregidas y el pipeline debe **aprobarla**.

## Qué revisa el pipeline

| Etapa | Qué busca | Herramienta |
| --- | --- | --- |
| 1. Secretos | Llaves y contraseñas en el código | Gitleaks 8.30.1 |
| 2. SAST | Fallas en el código fuente (SQLi, eval, shell=True...) | Semgrep 1.183.0 + reglas propias |
| 3. SCA | Dependencias con CVE conocidos | pip-audit 2.10.1 |
| 4. Configuración | Dockerfile inseguro + SBOM (CycloneDX) | Trivy 0.76.1 |
| 5. Imagen | CVE HIGH/CRITICAL con parche disponible en la imagen Docker (`--ignore-unfixed`) | Trivy |
| 6. DAST | Ataques sobre la app en ejecución | OWASP ZAP baseline |
| Gate | Aprueba o rechaza según los hallazgos | `scripts/summarize.py` |

## Estructura

```text
.github/workflows/devsecops.yml   pipeline (matriz: vulnerable-app y fixed-app)
.github/dependabot.yml            mantiene actualizados los hashes de las actions
semgrep-rules/python-security.yml reglas SAST propias (7 reglas)
scripts/run_local.sh              corre 4 escáneres en tu equipo y mide tiempos
scripts/summarize.py              tabla de resultados, métricas y quality gate
scripts/timed.sh                  mide cuántos segundos tarda cada escáner
vulnerable-app/                   app con fallas a propósito
fixed-app/                        app corregida
```
