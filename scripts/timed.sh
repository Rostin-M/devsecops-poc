#!/usr/bin/env bash
# Ejecuta un comando, anota cuántos segundos tardó en $RESULTS/timings.txt y devuelve su código de salida.
# Uso: RESULTS=results/app bash scripts/timed.sh <nombre> <comando> [argumentos...]
# Formato de cada línea: "<nombre> <segundos> <código de salida>" (lo lee scripts/summarize.py).
nombre="$1"
shift
mkdir -p "${RESULTS:?define RESULTS}"
inicio=$(date +%s.%N)
"$@"
codigo=$?
fin=$(date +%s.%N)
awk -v n="$nombre" -v a="$inicio" -v b="$fin" -v c="$codigo" 'BEGIN { printf "%s %.2f %d\n", n, b - a, c }' >> "${RESULTS}/timings.txt"
exit "$codigo"
