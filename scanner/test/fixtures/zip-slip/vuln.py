import tarfile

def unpack_vuln(tar_path, dest):
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)

def unpack_safe(tar_path, dest):
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest, filter='data')
