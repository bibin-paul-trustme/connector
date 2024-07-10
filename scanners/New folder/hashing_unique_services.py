
import hashlib

def hashing_values(severity, summary, description, filename, issue_category, line):
    hashing_values = (severity, summary, description, filename, issue_category, line)
    hashed_value = hashlib.md5(str(hashing_values).encode()).hexdigest()
    return hashed_value