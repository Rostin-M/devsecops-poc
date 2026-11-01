#!/usr/bin/env bash
# Corre los escáneres de la PoC sobre una carpeta y guarda resultados + tiempos.
# Uso: scripts/run_local.sh vulnerable-app   (o fixed-app)
set -uo pipefail

TARGET="${1:?Uso: $0 <vulnerable-app|fixed-app>}"
OUT="results/${TARGET}"
mkdir -p "${OUT}"
: > "${OUT}/timings.txt"

# Mide cuánto tarda cada herramienta (segundos) y guarda el código de salida.
timed() {
  local name="$1"; shift
  local t0 t1
  t0=$(date +%s.%N)
  "$@"
  local rc=$?
  t1=$(date +%s.%N)
  printf '%s %.2f %s\n' "${name}" "$(echo "${t1} - ${t0}" | bc -l)" "${rc}" >> "${OUT}/timings.txt"
}

echo "==> [1/4] Secretos: Gitleaks"
timed gitleaks gitleaks dir "${TARGET}" --no-banner --redact \
  --report-format json --report-path "${OUT}/gitleaks.json" --exit-code 0

echo "==> [2/4] SAST: Semgrep (reglas locales)"
timed semgrep semgrep scan --metrics=off --quiet --disable-version-check \
  --config semgrep-rules/ --json --output "${OUT}/semgrep.json" "${TARGET}"

echo "==> [3/4] SCA: pip-audit sobre requirements.txt"
timed pip-audit pip-audit -r "${TARGET}/requirements.txt" --no-deps --disable-pip \
  -f json -o "${OUT}/pip-audit.json" || true

echo "==> [4/4] Misconfiguración: Trivy sobre el Dockerfile"
timed trivy-config trivy config --quiet --format json \
  --output "${OUT}/trivy-config.json" "${TARGET}"

python3 scripts/summarize.py "${OUT}" --target "${TARGET}"
