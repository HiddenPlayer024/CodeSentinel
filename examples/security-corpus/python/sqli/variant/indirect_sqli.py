import sqlite3

def get_user_data(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Indirect SQLi where query is built dynamically
    base_query = "SELECT * FROM users WHERE username = '%s'"
    final_query = base_query % user_input
    cursor.execute(final_query)
    return cursor.fetchall()
