import sqlite3

def get_user_data(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Safe usage
    base_query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(base_query, (user_input,))
    return cursor.fetchall()
