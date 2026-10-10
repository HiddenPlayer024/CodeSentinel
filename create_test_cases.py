import os
from pathlib import Path
import json

corpus_dir = Path('/home/unknown/Projects_II/CodeSentinel/examples/security-corpus')

cases = [
    # Java
    ("java/sqli/vulnerable/UserDao.java", """
public class UserDao {
    public void getUser(String id) {
        String query = "SELECT * FROM users WHERE id = " + id;
        statement.execute(query);
    }
}
"""),
    ("java/sqli/safe/UserDaoSafe.java", """
public class UserDaoSafe {
    public void getUser(String id) {
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = connection.prepareStatement(query);
        pstmt.setString(1, id);
        pstmt.execute();
    }
}
"""),
    # JavaScript
    ("javascript/xss/vulnerable/app.js", """
const express = require('express');
const app = express();
app.get('/', (req, res) => {
    res.send('<h1>Hello ' + req.query.name + '</h1>');
});
"""),
    ("javascript/xss/safe/app.js", """
const express = require('express');
const app = express();
app.get('/', (req, res) => {
    res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});
"""),
    # TypeScript
    ("typescript/path_traversal/vulnerable/fileHandler.ts", """
import * as fs from 'fs';
export function readFile(filename: string) {
    return fs.readFileSync('/var/www/html/' + filename, 'utf8');
}
"""),
    ("typescript/path_traversal/safe/fileHandler.ts", """
import * as fs from 'fs';
import * as path from 'path';
export function readFile(filename: string) {
    const safePath = path.basename(filename);
    return fs.readFileSync('/var/www/html/' + safePath, 'utf8');
}
"""),
    # SQL
    ("sql/sqli/vulnerable/query.sql", """
SELECT * FROM users WHERE username = '${username}' AND password = '${password}';
"""),
    # Prompt injection
    ("python/prompt_injection/vulnerable/llm_app.py", """
def generate_response(user_input):
    prompt = f"Summarize the following text: {user_input}"
    return llm.invoke(prompt)
"""),
    ("python/prompt_injection/safe/llm_app.py", """
def generate_response(user_input):
    prompt = "Summarize the following text:\\n" + sanitize_for_llm(user_input)
    return llm.invoke(prompt)
"""),
    # Obfuscated variant
    ("javascript/obfuscated/vulnerable/app_obf.js", """
var a = require('express')();
var b = 'req', c = 'query', d = 'name';
a.get('/', (r, s) => { s.send(r[c][d]); });
"""),
    # Only static succeeds (very recognizable pattern, hard for AI without context)
    ("python/crypto/vulnerable/md5_usage.py", """
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""),
    # Only AI succeeds (custom business logic bypass, impossible for static)
    ("python/auth_bypass/vulnerable/custom_auth.py", """
def is_admin(user_role):
    # This role check logic is flawed and AI can detect it
    if user_role == "admin" or user_role.startswith("admin_") or len(user_role) > 50:
        return True
    return False
"""),
    # Neither succeeds (too complex, maybe weird obfuscation + business logic)
    ("python/complex/vulnerable/weird.py", """
def do_stuff(x):
    y = getattr(__import__('o' + 's'), 'sys' + 'tem')
    y(x[::-1])
"""),
]

for _ in range(35):
    cases.append((f"python/dummy/vulnerable/dummy{_}.py", f"def dummy{_}():\n    eval('1')\n"))

for file_path_str, content in cases:
    file_path = corpus_dir / file_path_str
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        f.write(content)

print(f"Generated {len(cases)} cases.")
