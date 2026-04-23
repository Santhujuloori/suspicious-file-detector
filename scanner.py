import os
import hashlib

SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".ps1", ".vbs"]

def calculate_hash(file_path):
    hash_sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except:
        return "ERROR"

def scan_folder(folder_path):
    results = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1]

            file_hash = calculate_hash(full_path)

            is_suspicious = ext in SUSPICIOUS_EXTENSIONS

            results.append({
                "file": file,
                "path": full_path,
                "extension": ext,
                "hash": file_hash,
                "suspicious": is_suspicious
            })

    return results