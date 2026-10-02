import os
def change_perms(path):
    os.chmod(path, 0o777)
