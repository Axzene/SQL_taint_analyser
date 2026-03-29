# sample_mixed.py

import sqlite3


# =====================================================================
# ORIGINAL SQL TEST CASES
# =====================================================================

# Database Connection (Beginner style)

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

# User Login Feature (SAFE - parameterized)

username = input("Enter username: ")
password = input("Enter password: ")

login_query = "SELECT * FROM users WHERE username = "+username+"AND password = "+password
cursor.execute(login_query)

# Search Feature (VULNERABLE - f-string)

search_term = input("Search user: ")
search_query = f"SELECT * FROM users WHERE username = '{search_term}'"
cursor.execute(search_query)

# Profile Lookup (SAFE - parameterized)

user_id = input("Enter user ID: ")
profile_query = "SELECT * FROM users WHERE id = ?"
cursor.execute(profile_query, (user_id,))

# Update Email (VULNERABLE - format())

new_email = input("Enter new email: ")
update_query = "UPDATE users SET email = '{}' WHERE id = {}".format(new_email, user_id)
cursor.execute(update_query)

# Safe Insert Example (SAFE)

new_user = input("New username: ")
safe_insert = "INSERT INTO users(username) VALUES (?)"
cursor.execute(safe_insert, (new_user,))

# Static Query (SAFE - no user input)

cursor.execute("SELECT COUNT(*) FROM users")

connection.commit()
connection.close()



raw_name = input("Enter name to search: ")
results = User.objects.raw("SELECT * FROM users WHERE name = '" + raw_name + "'")



raw_search = input("Enter search term: ")
raw_query = "SELECT * FROM users WHERE username = '" + raw_search + "'"
results = User.objects.raw(raw_query)



filter_input = input("Filter by username: ")
results = User.objects.filter(filter_input)



lookup_id = input("Enter user ID to look up: ")
user_record = User.objects.get(lookup_id)



text_id = input("Enter ID: ")
result = session.execute(text("SELECT * FROM users WHERE id = " + text_id))


safe_raw_name = input("Enter name: ")
results = User.objects.raw("SELECT * FROM users WHERE name = %s", [safe_raw_name])



bp_user_id = input("Enter ID: ")
safe_bp = bindparam(bp_user_id)
result = session.execute("SELECT * FROM users WHERE id = :id", {"id": safe_bp})
