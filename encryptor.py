import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
getpass = input

def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file():
    path = input("Enter file path to encrypt: ").strip()
    if not os.path.exists(path):
        print("❌ File not found.")
        return
    pwd = input("Enter encryption password: ")
    salt = os.urandom(16)
    key = generate_key(pwd, salt)
    fernet = Fernet(key)

    with open(path, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(salt + encrypted_data)
    print(f"✅ File encrypted successfully! Saved as: {out_path}")

def decrypt_file():
    path = input("Enter .enc file path to decrypt: ").strip()
    if not os.path.exists(path):
        print("❌ File not found.")
        return
    pwd = input("Enter decryption password: ")

    with open(path, "rb") as f:
        file_content = f.read()

    salt = file_content[:16]
    encrypted_data = file_content[16:]
    key = generate_key(pwd, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        base = path[:-4] if path.endswith(".enc") else path
        root, ext = os.path.splitext(base)
        out_path = f"{root}_decrypted{ext or '.txt'}"
        with open(out_path, "wb") as f:
            f.write(decrypted_data)
        print(f"✅ File decrypted successfully! Saved as: {out_path}")
    except Exception:
        print("❌ Decryption failed! Incorrect password or corrupted file.")

def main():
    while True:
        print("\n==========================================")
        print("      SECURE FILE ENCRYPTION TOOL         ")
        print("==========================================")
        print("1. Encrypt File (AES)")
        print("2. Decrypt File (AES)")
        print("3. Exit")
        print("------------------------------------------")
        choice = input("Enter choice (1-3): ").strip()
        if choice == "1": encrypt_file()
        elif choice == "2": decrypt_file()
        elif choice == "3": break

if __name__ == "__main__":
    main()
