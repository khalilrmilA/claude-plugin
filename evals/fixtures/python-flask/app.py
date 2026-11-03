import os
import sqlite3
import subprocess
import pickle
import base64
import hashlib
import logging

from flask import Flask, request, redirect, render_template_string, send_file

app = Flask(__name__)
app.config["DEBUG"] = True
app.secret_key = "sk_live_hardcoded_session_key_do_not_use_123456"

log = logging.getLogger("app")


def db():
    return sqlite3.connect("app.db")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    con = db()
    rows = con.execute(
        "SELECT id, name FROM products WHERE name LIKE '%" + q + "%'"
    ).fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    out = subprocess.check_output("ping -c1 " + host, shell=True)
    return out


@app.route("/render")
def render():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/download")
def download():
    fname = request.args.get("file", "")
    return send_file(os.path.join("/var/data", fname))


@app.route("/load", methods=["POST"])
def load():
    blob = request.form.get("state", "")
    data = pickle.loads(base64.b64decode(blob))
    return {"loaded": str(data)}


@app.route("/go")
def go():
    nxt = request.args.get("next", "/")
    return redirect(nxt)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log.info("login attempt user=%s password=%s", username, password)
    digest = hashlib.md5(password.encode()).hexdigest()
    con = db()
    row = con.execute(
        "SELECT id FROM users WHERE name = ? AND pw = ?", (username, digest)
    ).fetchone()
    return {"ok": bool(row)}


@app.route("/admin/users")
def admin_users():
    con = db()
    rows = con.execute("SELECT id, name, email FROM users").fetchall()
    return {"users": rows}


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
