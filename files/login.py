# Implementation of a login function, that is also in charge of the creation of accounts
import os
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey
import pki

DB_FILE = 'users.json'

# Helper functions to manage database loading and saving
def load_db():
    try:
        with open(DB_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If file doesn't exist or is empty/corrupt, start with an empty structure
        return {"users": []}

def save_db(data):
    with open(DB_FILE, 'w') as file:
        json.dump(data, file, indent=4)

def find_user(usertofind):
    # check the json database we have for the existence of the username
    try:
        with open(DB_FILE, 'r') as file:
            data = json.load(file)
            userlist = data.get('users', [])
            for user in userlist:
                if user['username'] == usertofind:
                    return user
            return None
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# The creation of the register function, we will store the usernames in plaintext

def special_check(password):
    special_characters = "!@#$%^&*()_-+={[}]|\\:;'<,>.?/"
    count = 0
    for char in password:
        if char in special_characters:
            count += 1
    if count >= 2:
        return True
    else:
        return False


def register():
    username = input("Introduce your username: ")
    if find_user(username):
        print("Username already exists, choose other username")
        return

    password = input("Introduce your password (length > 8, >= 2 special chars): ")
    if not (len(password) > 8 and special_check(password)):
        print("Password does not meet requirements.")
        return

    # gen keys and csr
    print("Generating RSA key pair and CSR...")
    rsa_private, rsa_public = pki.generate_rsa_keypair()
    pem_private_encrypted = pki.serialize_private_key(rsa_private, password.encode('utf-8'))
    csr = pki.generate_csr(rsa_private, username)

    # Save CSR to a file for the user
    csr_filename = f"{username}_csr.pem"
    with open(csr_filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("\n--- ACTION REQUIRED ---")
    print(f"A CSR file named '{csr_filename}' has been created.")
    print("1. Take this file to your OpenSSL CA.")
    print(f"2. Run: openssl ca -in {csr_filename} -out {username}_cert.pem -config openssl_CA1.cnf")
    print(f"3. Place the generated '{username}_cert.pem' file in this directory.")
    input("Press Enter after you have done this...")

    # Load the signed certificate and create the user
    try:
        user_cert_path = f"{username}_cert.pem"
        user_cert = pki.load_certificate_from_pem_file(user_cert_path)
        user_cert_pem = user_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        print("Certificate loaded successfully.")
    except FileNotFoundError:
        print(f"ERROR: Certificate file '{user_cert_path}' not found. Registration cancelled.")
        os.remove(csr_filename)
        return
    except Exception as e:
        print(f"ERROR: Could not load certificate. {e}. Registration cancelled.")
        os.remove(csr_filename)
        return

    data = load_db()
    max_id = max((user['id'] for user in data.get('users', [])), default=0)
    next_id = max_id + 1

    # generated a salt of 16 bytes
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    key_salt = os.urandom(16)
    kdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=key_salt,
        iterations=1_200_000,
    )
    aes_key = os.urandom(32) # Generate random key
    aesgcm = AESGCM(aes_key)
    p_balance = str(0.0).encode('utf-8')
    nonce = os.urandom(16)
    encrypted_balance = aesgcm.encrypt(nonce, p_balance, None)
    
    encrypted_aes_key_hex = pki.rsa_encrypt_key(rsa_public, aes_key)

    new_user = {
        "id": next_id,
        "username": username,
        "salt": salt.hex(),
        "password_hash": hashed_password.hex(),
        "key_salt": key_salt.hex(),
        "encrypted_balance": encrypted_balance.hex(),
        "bal_nonce": nonce.hex(),
        "encrypted_aes_key": encrypted_aes_key_hex,
        "user_certificate_pem": user_cert_pem,
        "rsa_private_key_pem": pem_private_encrypted,
        "last_balance_signature": None
    }

    if 'users' not in data:
        data['users'] = []
    data["users"].append(new_user)
    save_db(data)

    print("Your registration was successful!")
    os.remove(csr_filename)
    os.remove(user_cert_path)
    return True


# the login function should be easy, we ask for a user, a password, and then we use scrypt and the salt (corresponding to the username) we have to hash said password
# and then we check the database to see if they both match, i can see why this method is secure, because the attacker couldn't know the salt because this all would be done server side

def login():
    username = input("Introduce an username: ")
    password = input("Introduce the password: ")
    userdata = find_user(username)

    if userdata:
        salt_hex = userdata['salt']
        hash_hex = userdata['password_hash']
        saltkey_hex = userdata['key_salt']

        # as we stored it in hex, we need to convert it to bytes
        key_salt = bytes.fromhex(saltkey_hex)

        # This part just derives the key to return it, it doesn't verify the user
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_salt,
            iterations=1_200_000,
        )
        key = kdf2.derive(password.encode('utf-8'))

        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )

        try:
            # This is the actual password verification
            kdf.verify(password.encode('utf-8'), stored_hash)
            print(f"Verification successful. Welcome, {username}!")
            print("Loading and decrypting your private key...")
            pem_private_encrypted = userdata['rsa_private_key_pem']
            rsa_private_key = pki.load_private_key(pem_private_encrypted, password.encode('utf-8'))
            print("Private key loaded.")

            return (userdata, key, rsa_private_key) 

        except InvalidKey:
            print("Invalid username or password.")
            return (None, None, None) 
        except Exception as e:
            print(f"Invalid username or password (or key decryption failed): {e}")
            return (None, None, None) 

    else:
        print("Invalid username or password.")
        return (None, None, None)
