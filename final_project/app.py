import os

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
# used microsoft copilot to learn how to use SQL
import sqlite3

# Connect to an SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('example.db')

# Create a cursor object to interact with the database
cursor = conn.cursor()

# Create a table
cursor.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    age INTEGER
                  )''')

# Insert a new record
cursor.execute('''INSERT INTO users (name, age) VALUES (?, ?)''', ('John Doe', 30))

# Commit the transaction
conn.commit()

# Query the database
cursor.execute('''SELECT * FROM users''')
rows = cursor.fetchall()

for row in rows:
    print(row)

# Close the connection
conn.close()
