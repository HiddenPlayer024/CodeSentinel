import subprocess, shlex

def execute_user_command(user_input):
    safe_input = shlex.quote(user_input)
    subprocess.run(["ping", "-c", "1", user_input], check=True)
