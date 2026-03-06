# sample_mixed.py

import sqlite3

# ----------------------------------------------------
# Database Connection (Beginner style)
# ----------------------------------------------------

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

# ----------------------------------------------------
# User Login Feature (VULNERABLE - concatenation)
# ----------------------------------------------------

username = input("Enter username: ")
password = input("Enter password: ")

login_query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
cursor.execute(login_query)

# ----------------------------------------------------
# Search Feature (VULNERABLE - f-string)
# ----------------------------------------------------

search_term = input("Search user: ")
search_query = f"SELECT * FROM users WHERE username = '{search_term}'"
cursor.execute(search_query)

# ----------------------------------------------------
# Profile Lookup (SAFE - parameterized)
# ----------------------------------------------------

user_id = input("Enter user ID: ")
profile_query = "SELECT * FROM users WHERE id = ?"
cursor.execute(profile_query, (user_id,))

# ----------------------------------------------------
# Update Email (VULNERABLE - format())
# ----------------------------------------------------

new_email = input("Enter new email: ")
update_query = "UPDATE users SET email = '{}' WHERE id = {}".format(new_email, user_id)
cursor.execute(update_query)

# ----------------------------------------------------
# Safe Insert Example (SAFE)
# ----------------------------------------------------

new_user = input("New username: ")
safe_insert = "INSERT INTO users(username) VALUES (?)"
cursor.execute(safe_insert, (new_user,))

# ----------------------------------------------------
# Static Query (SAFE - no user input)
# ----------------------------------------------------

cursor.execute("SELECT COUNT(*) FROM users")

connection.commit()
connection.close()