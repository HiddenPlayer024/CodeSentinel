import sqlite3

def sanitize(val):
    return val.replace("'", "''")

def direct_vulnerability(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Direct vulnerability
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)

def var_vulnerability(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Vulnerability through variable
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)

def safe_parameterized(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Safe parameterized query
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))

def constant_input():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Constant input
    query = "SELECT * FROM users WHERE id=42"
    cursor.execute(query)

def sanitized_input(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Sanitized input
    user_id = sanitize(user_id)
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)

def multi_hop(request_data):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Multiple-hop propagation
    var_a = request_data
    var_b = var_a + " extra"
    var_c = "SELECT * FROM users WHERE id=" + var_b
    cursor.execute(var_c)
