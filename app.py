"""
TaskFlow - versao corrigida (Aulas 2 e 3).

Correcoes em relacao a linha de base:
  1. SQL Injection (login e busca): consultas parametrizadas.
  2. XSS: HTML renderizado por templates Jinja2 com autoescape.
  3. SECRET_KEY lida de variavel de ambiente (a app recusa subir sem ela).
  4. Senhas armazenadas com hash (werkzeug.security); sem senha fixa no codigo.
  5. Endpoint /debug/info removido.
  6. debug nunca fixo em True; em producao roda gunicorn (ver Dockerfile).
"""

import os
import sqlite3

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variavel de ambiente {name} nao foi definida.")
    return value


app = Flask(__name__)
app.config["SECRET_KEY"] = _require_env("TASKFLOW_SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = os.environ.get("TASKFLOW_DB", "taskflow.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()

    # Senhas iniciais vem do ambiente e so o HASH vai para o banco.
    # INSERT OR IGNORE evita corrida quando varios workers iniciam juntos.
    seed = (
        ("admin", _require_env("ADMIN_PASSWORD")),
        ("aluno", _require_env("ALUNO_PASSWORD")),
    )
    for username, password in seed:
        db.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
    db.commit()


# Com gunicorn o bloco __main__ nao roda, entao o banco e iniciado no import.
with app.app_context():
    init_db()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        error = "Usuario ou senha invalidos."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    if search:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], "%" + search + "%"),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    return render_template("tasks.html", rows=rows, username=session["username"])


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db = get_db()
        db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()
        return redirect(url_for("tasks"))

    return render_template("new_task.html")


if __name__ == "__main__":
    # Execucao local apenas. Em producao: gunicorn (Dockerfile).
    app.run(
        host=os.environ.get("TASKFLOW_HOST", "127.0.0.1"),
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
