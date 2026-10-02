import os, sys

def execute_user_command(user_input):
    os.system(f"ping -c 1 {user_input}")
