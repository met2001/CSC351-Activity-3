import sqlite3
import os

DB = "lostfound.db"
if os.path.exists(DB):
    print("Removing old DB")
    os.remove(DB)

conn = sqlite3.connect(DB)
c = conn.cursor()

# Users table: username, password (plaintext intentionally), role
c.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
''')

# Lost items: owner (username), title, description, image filename, resolved flag
c.execute('''
CREATE TABLE lost_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    image TEXT,
    resolved INTEGER DEFAULT 0
)
''')

# Found items: posted_by, title, description, image, returned flag
c.execute('''
CREATE TABLE found_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    posted_by TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    image TEXT,
    returned INTEGER DEFAULT 0
)
''')

# Seed users
c.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'password123', 'user')")
c.execute("INSERT INTO users (username, password, role) VALUES ('staff', 'adminpass', 'staff')")

# Seed some items (note: descriptions include HTML to demonstrate XSS)
c.execute("INSERT INTO lost_items (owner, title, description, image) VALUES (?, ?, ?, ?)",
          ("alice", "Blue Backpack", "Blue backpack with <b>laptop</b>", None))
c.execute("INSERT INTO found_items (posted_by, title, description, image) VALUES (?, ?, ?, ?)",
          ("staff", "Black Umbrella", "Found near library. Contact staff", None))

conn.commit()
conn.close()
print("Database initialized as", DB)
