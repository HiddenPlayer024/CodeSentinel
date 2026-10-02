import subprocess

def execute_user_command(user_input):
    # Using Popen with shell=True is also vulnerable
    subprocess.Popen(f"ping -c 1 {user_input}", shell=True)
