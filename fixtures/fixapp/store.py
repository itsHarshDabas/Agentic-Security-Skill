"""User store. Intentionally vulnerable; see README.md."""
import hashlib
import sqlite3


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, pw TEXT)")
    return conn


def add_user(conn, name, password):
    conn.execute("INSERT INTO users (name, pw) VALUES (?, ?)", (name, hash_password(password)))


def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"static-demo-salt", 100_000).hex()


def find_user(conn, name):
    return conn.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
