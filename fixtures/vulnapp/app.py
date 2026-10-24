"""Tiny invoice service. Intentionally vulnerable; see README.md."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, abort, g, jsonify, redirect, render_template_string, request, send_file, session

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-123"  # SEED:hardcoded-flask-secret
DB = os.environ.get("DB_PATH", "/tmp/vulnapp.db")
UPLOADS = "/srv/uploads"


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
    return g.db


def current_user():
    return session.get("user_id")


@app.route("/login", methods=["POST"])
def login():
    name = request.form["username"]
    pw = request.form["password"]
    digest = hashlib.md5(pw.encode()).hexdigest()  # SEED:weak-password-hash
    row = db().execute(
        f"SELECT id FROM users WHERE name = '{name}' AND pw = '{digest}'"  # SEED:sqli-login
    ).fetchone()
    if not row:
        abort(401)
    session["user_id"] = row[0]
    return redirect(request.args.get("next", "/"))  # SEED:open-redirect


@app.route("/invoices/<int:invoice_id>")
def get_invoice(invoice_id):
    if not current_user():
        abort(401)
    # Any logged-in user can read any invoice: no owner check.
    row = db().execute("SELECT id, owner_id, total FROM invoices WHERE id = ?", (invoice_id,)).fetchone()  # SEED:idor-invoice
    return jsonify(id=row[0], owner=row[1], total=row[2])


@app.route("/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):
    if current_user() != user_id:
        abort(403)
    fields = request.get_json()
    cols = ", ".join(f"{k} = ?" for k in fields)  # SEED:mass-assignment
    db().execute(f"UPDATE users SET {cols} WHERE id = ?", (*fields.values(), user_id))  # SEED:sqli-column-names
    return "", 204


@app.route("/admin/export")
def admin_export():
    # Missing role check: only authentication is enforced.
    if not current_user():  # SEED:missing-admin-authz
        abort(401)
    return send_file(DB)


@app.route("/files")
def download():
    name = request.args["name"]
    return send_file(os.path.join(UPLOADS, name))  # SEED:path-traversal


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # SEED:command-injection
    return out


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    return requests.get(url, timeout=5).text  # SEED:ssrf


@app.route("/import", methods=["POST"])
def import_settings():
    cfg = yaml.load(request.data)  # SEED:unsafe-yaml
    return jsonify(cfg)


@app.route("/restore", methods=["POST"])
def restore():
    state = pickle.loads(request.data)  # SEED:unsafe-pickle
    return jsonify(ok=bool(state))


@app.route("/hello")
def hello():
    return render_template_string("Hello " + request.args.get("name", "")) # SEED:ssti


# ---- Safe code that scanners commonly flag ---------------------------------

@app.route("/search")
def search():
    term = request.args.get("q", "")
    rows = db().execute("SELECT id FROM invoices WHERE memo LIKE ?", (f"%{term}%",)).fetchall()  # DECOY:parameterized-query
    return jsonify([r[0] for r in rows])


@app.route("/version")
def version():
    out = subprocess.run(["git", "--version"], capture_output=True, text=True)  # DECOY:fixed-argv-subprocess
    return out.stdout


def etag(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # DECOY:md5-etag


def jitter() -> float:
    return random.random() * 0.1  # DECOY:random-jitter


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # SEED:flask-debug
