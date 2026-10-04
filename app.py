import json
import os
import re
import secrets
import sqlite3
import subprocess  # nosec B404 - only used for ping: no shell, argument list, validated host
from functools import wraps

from flask import Flask, Response, g, redirect, request, session
from jinja2 import Environment, FileSystemLoader, select_autoescape
from werkzeug.security import check_password_hash

DATABASE = "notes.db"

# FIX #6: the secret comes from the environment, never from the source code
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set, using a random key (sessions are lost on restart)")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# FIX #5: automatic escaping for HTML templates
templates = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html"]),
)

# Hostname or IPv4: letters, digits, dots and hyphens; must not start with a hyphen
HOST_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

DEFAULT_PREFS = {"theme": "light", "notes_per_page": 20}
ALLOWED_THEMES = {"light", "dark"}


def render(name, **context):
    context.setdefault("user", session.get("username"))
    return templates.get_template(name).render(**context)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return redirect("/notes" if "user_id" in session else "/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # FIX #1: parameterized query
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # FIX #4: password check with a slow, salted hash
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/notes")
        error = "Wrong credentials"
    return render("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/notes")
@login_required
def notes():
    q = request.args.get("q", "")

    # FIX #1 (bis): parameterized query, the % wildcards are part of the value
    rows = get_db().execute(
        "SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ?",
        (session["user_id"], f"%{q}%"),
    ).fetchall()

    return render("notes.html", notes=rows, q=q)


@app.route("/notes/new", methods=["POST"])
@login_required
def new_note():
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (session["user_id"], request.form["title"], request.form["content"]),
    )
    db.commit()
    return redirect("/notes")


@app.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    note = get_db().execute(
        "SELECT title, content FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()
    if note is None:
        return "Note not found", 404
    return render("note.html", note=note)


@app.route("/admin/ping")
@login_required
def ping():
    host = request.args.get("host", "")
    output = None
    error = None
    if host:
        # FIX #2: input validation + no shell + absolute path
        if not HOST_PATTERN.fullmatch(host):
            error = "Invalid host: only letters, digits, dots and hyphens are allowed."
        else:
            result = subprocess.run(  # nosec B603 - no shell, argument list, host validated by HOST_PATTERN
                ["/usr/bin/ping", "-c", "1", host],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout + result.stderr
    return render("ping.html", host=host, output=output, error=error)


def parse_prefs(raw):
    """Validate a JSON preferences file. Raise ValueError if invalid."""
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("invalid format")

    theme = data.get("theme", DEFAULT_PREFS["theme"])
    per_page = data.get("notes_per_page", DEFAULT_PREFS["notes_per_page"])

    if theme not in ALLOWED_THEMES:
        raise ValueError("invalid theme")
    if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= 100:
        raise ValueError("invalid notes_per_page")

    return {"theme": theme, "notes_per_page": per_page}


@app.route("/profile/export")
@login_required
def export_prefs():
    prefs = session.get("prefs", DEFAULT_PREFS)
    return Response(
        json.dumps(prefs),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=prefs.json"},
    )


@app.route("/profile/import", methods=["GET", "POST"])
@login_required
def import_prefs():
    message = None
    if request.method == "POST":
        # FIX #3: JSON + schema validation instead of pickle
        try:
            prefs = parse_prefs(request.files["prefs"].read())
        except ValueError:
            message = "Invalid preferences file."
        else:
            session["prefs"] = prefs
            message = "Preferences imported successfully."
    return render("profile.html", message=message, prefs=session.get("prefs"))


if __name__ == "__main__":
    # FIX #7: debug disabled by default, enabled explicitly with FLASK_DEBUG=1
    # B104: listen on 127.0.0.1 by default; the container opts into 0.0.0.0 via APP_HOST
    host = os.environ.get("APP_HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host=host, port=5000, debug=debug)