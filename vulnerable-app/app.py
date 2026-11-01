"""Mini tienda: APP VULNERABLE A PROPÓSITO para la prueba de concepto DevSecOps.

NO usar en producción. NO usar en producción. Cada falla está marcada con la herramienta que la detecta.
Todas las credenciales de este archivo son falsas (inventadas para la demo).
"""
import hashlib
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

# [SECRETOS -> Gitleaks] Credenciales falsas escritas directo en el código
API_KEY = "x9Kd82LmQ4vTz7PwB1nR6yHc3JfUa5Es"
DB_PASSWORD = "Sup3rS3cr3t!2024xYz"


def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE productos (id INTEGER, nombre TEXT, precio REAL)")
    conn.executemany(
        "INSERT INTO productos VALUES (?, ?, ?)",
        [(1, "cafe", 12.5), (2, "te", 8.0), (3, "chocolate", 15.0)],
    )
    return conn


DB = get_db()


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
    # [SAST -> Semgrep] Inyección SQL: la consulta se arma concatenando texto del usuario
    query = f"SELECT id, nombre, precio FROM productos WHERE nombre LIKE '%{nombre}%'"
    return jsonify(DB.execute(query).fetchall())


@app.route("/calcular")
def calcular():
    # [SAST -> Semgrep] eval() sobre entrada del usuario permite ejecutar código
    return str(eval(request.args.get("expr", "0")))


@app.route("/config", methods=["POST"])
def config():
    # [SAST -> Semgrep] yaml.load con Loader completo permite construir objetos arbitrarios
    return jsonify(yaml.load(request.data, Loader=yaml.Loader))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [SAST -> Semgrep] Inyección de comandos: shell=True con texto del usuario
    salida = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return salida.stdout


@app.route("/login", methods=["POST"])
def login():
    clave = request.form.get("clave", "")
    # [SAST -> Semgrep] MD5 no es apto para guardar contraseñas
    huella = hashlib.md5(clave.encode()).hexdigest()
    return jsonify({"huella": huella})


if __name__ == "__main__":
    # [SAST -> Semgrep] debug=True expone la consola interactiva de Werkzeug
    app.run(host="0.0.0.0", port=8080, debug=True)
