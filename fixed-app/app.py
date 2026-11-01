"""Mini tienda: versión corregida de la app vulnerable.

Mismos endpoints, pero cada falla del análisis de seguridad está resuelta.
"""
import ast
import ipaddress
import operator
import os
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash

app = Flask(__name__)

# Los secretos vienen del entorno (en CI, de GitHub Secrets), nunca del código
API_KEY = os.environ.get("API_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")


def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE productos (id INTEGER, nombre TEXT, precio REAL)")
    conn.executemany(
        "INSERT INTO productos VALUES (?, ?, ?)",
        [(1, "cafe", 12.5), (2, "te", 8.0), (3, "chocolate", 15.0)],
    )
    return conn


DB = get_db()

OPERADORES = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


def evaluar(nodo):
    """Evalúa solo números y + - * /, sin ejecutar código arbitrario."""
    if isinstance(nodo, ast.Expression):
        return evaluar(nodo.body)
    if isinstance(nodo, ast.Constant) and isinstance(nodo.value, (int, float)):
        return nodo.value
    if isinstance(nodo, ast.BinOp) and type(nodo.op) in OPERADORES:
        return OPERADORES[type(nodo.op)](evaluar(nodo.left), evaluar(nodo.right))
    raise ValueError("expresión no permitida")


@app.after_request
def cabeceras_seguras(resp):
    # form-action y frame-ancestors no heredan de default-src: hay que declararlos (ZAP lo exigió)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return resp


@app.route("/")
def index():
    return (
        "<h1>Mini tienda</h1><ul>"
        "<li><a href='/producto?nombre=cafe'>Buscar producto</a></li>"
        "<li><a href='/calcular?expr=2*3'>Calculadora</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>Ping</a></li>"
        "</ul>"
    )


@app.route("/producto")
def producto():
    nombre = request.args.get("nombre", "")
    # Consulta parametrizada: el texto del usuario nunca se mezcla con el SQL
    filas = DB.execute(
        "SELECT id, nombre, precio FROM productos WHERE nombre LIKE ?",
        (f"%{nombre}%",),
    ).fetchall()
    return jsonify(filas)


@app.route("/calcular")
def calcular():
    try:
        arbol = ast.parse(request.args.get("expr", "0"), mode="eval")
        return str(evaluar(arbol))
    except (ValueError, SyntaxError, ZeroDivisionError):
        return "expresión no válida", 400


@app.route("/config", methods=["POST"])
def config():
    # safe_load solo construye tipos simples (dict, list, str, números)
    try:
        return jsonify(yaml.safe_load(request.data))
    except yaml.YAMLError:
        # Etiquetas peligrosas (!!python/...) o YAML mal formado: rechazo limpio
        return "yaml no válido", 400


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)  # solo se acepta una IP válida
    except ValueError:
        return "host no válido", 400
    # Lista de argumentos y sin shell: no hay forma de inyectar comandos
    try:
        salida = subprocess.run(
            ["ping", "-c", "1", host], capture_output=True, text=True, check=False, timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # La imagen mínima (python:3.12-slim) no trae el binario ping. Antes esto era un
        # 500 con página de error; ahora es una respuesta controlada (lo detectó ZAP).
        return "ping no disponible en este contenedor", 503
    return salida.stdout


@app.route("/login", methods=["POST"])
def login():
    clave = request.form.get("clave", "")
    # Hash con sal y costo (scrypt vía Werkzeug), no MD5
    return jsonify({"hash": generate_password_hash(clave)})


if __name__ == "__main__":
    app.run(port=8080)
