import tarfile
def extract(tar_path):
    with tarfile.open(tar_path) as tar:
        tar.extractall()
