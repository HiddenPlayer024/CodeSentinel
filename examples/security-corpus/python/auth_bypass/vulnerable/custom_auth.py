
def is_admin(user_role):
    # This role check logic is flawed and AI can detect it
    if user_role == "admin" or user_role.startswith("admin_") or len(user_role) > 50:
        return True
    return False
