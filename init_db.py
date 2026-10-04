import hashlib
import sqlite3

DATABASE = "notes.db"

USERS = [
    ("admin", "admin123"),
    ("alice", "alice2026"),
    ("bob", "bob2026"),
]

NOTES = [
    (1, "My first note", "I really like this note taking application."),
    (2, "Recipe ingredients", "Milk, bread, coffee."),
    (2, "Random ideas", "Drone that kills mosquitos."),
    (3, "Meet reminder", "Thursday at 10AM."),
]

SCHEMA = """
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE notes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title    TEXT NOT NULL,
    content  TEXT NOT NULL
);
"""


def main():
    db = sqlite3.connect(DATABASE)
    db.executescript(SCHEMA)

    for username, password in USERS:
        password_hash = hashlib.md5(password.encode()).hexdigest()
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )

    db.executemany(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)", NOTES
    )
    db.commit()
    db.close()
    print(f"DB Initialized : {DATABASE}")


if __name__ == "__main__":
    main()