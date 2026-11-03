"""Files that look risky to a shallow scan but are safe. A good reviewer
reports NOTHING here. These exercise false-positive resistance."""
import sqlite3
import subprocess
import hashlib
from flask import Flask, request, escape

app = Flask(__name__)


@app.route("/safe-search")
def safe_search():
    # Parameterized query: q cannot change the statement structure.
    q = request.args.get("q", "")
    con = sqlite3.connect("app.db")
    rows = con.execute(
        "SELECT id, name FROM products WHERE name LIKE ?", ("%" + q + "%",)
    ).fetchall()
    return {"rows": rows}


@app.route("/safe-ping")
def safe_ping():
    # Fixed argument list, no shell, host validated against an allowlist.
    host = request.args.get("host", "")
    if host not in {"db.internal", "cache.internal"}:
        return {"error": "unknown host"}, 400
    out = subprocess.check_output(["ping", "-c1", host])
    return out


@app.route("/safe-hello")
def safe_hello():
    # Escaped output; not a template built from input.
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"


def content_digest(data: bytes) -> str:
    # MD5 here is a non-security content checksum, not a password hash.
    return hashlib.md5(data).hexdigest()
