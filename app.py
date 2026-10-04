import hashlib
import pickle
import sqlite3
import subprocess
from functools import wraps

from flask import Flask, Response, g, redirect, request, session
from jinja2 import Environment, FileSystemLoader

DATABASE = "notes.db"

# VULN n°6 : Hardcoded secret (Bandit B105)
SECRET_KEY = "dev-secret-change-me"

app = Flask(__name__)
app.secret_key = SECRET_KEY

# VULN n°5 : Classic XSS used non sanitized user input (Bandit B701)
templates = Environment(loader=FileSystemLoader("templates"), autoescape=False)


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

        # VULN n°4 : using MD5 hashing algorithm (Bandit B324)
        password_hash = hashlib.md5(password.encode()).hexdigest()

        # VULN n°1 : SQL Injection (Bandit B608)
        query = f"SELECT id, username FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        user = get_db().execute(query).fetchone()

        if user:
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

    # VULN n°1 (bis) : Classic SQL Injection (Bandit B608)
    query = f"SELECT id, title FROM notes WHERE owner_id = {session['user_id']} AND title LIKE '%{q}%'"
    rows = get_db().execute(query).fetchall()

    return render("notes.html", notes=rows, q=q)


@app.route("/notes/new", methods=["POST"])
@login_required
def new_note():
    # No SQL Injection
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
    if host:
        # VULN n°2 : Command injection, used with shell=true when spawning a subprocess (Bandit B602)
        result = subprocess.run(
            f"ping -n 1 {host}", shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
    return render("ping.html", host=host, output=output)


@app.route("/profile/export")
@login_required
def export_prefs():
    prefs = session.get("prefs", {"theme": "light", "notes_per_page": 20})
    return Response(
        pickle.dumps(prefs),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=prefs.pkl"},
    )


@app.route("/profile/import", methods=["GET", "POST"])
@login_required
def import_prefs():
    message = None
    if request.method == "POST":
        # VULN n°3 : User input deserealization (Bandit B301)
        prefs = pickle.loads(request.files["prefs"].read())
        session["prefs"] = prefs
        message = f"Preferences imported successfully : {prefs}"
    return render("profile.html", message=message, prefs=session.get("prefs"))


if __name__ == "__main__":
    # VULN n°7 : Debug mode activated (Bandit B201)
    # False positive : 0.0.0.0 is needed inside the container (Bandit B104)
    app.run(host="0.0.0.0", port=5000, debug=True)