# Implementation of a login function, that is also in charge of the creation of accounts
import os
import json
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey

DB_FILE = 'users.json'

def find_user(usertofind):
    # check the json database we have for the existence of the username
    try:
        with open('users.json', 'r') as file:
            data = json.load(file)
            userlist = data.get('users', [])  # if users doesn't exist .get would return none i think
            for user in userlist:
                if user['username'] == usertofind:
                    return user

            return None


    except FileNotFoundError:
        print("Error, the JSON file was not found")
        return None


# The creation of the register function, we will store the usernames in plaintext

def special_check(password):
    special_characters = "!@#$%^&*()_-+={[}]|\:;'<,>.?/"
    count = 0
    for char in password:
        if char in special_characters:
            count += 1
    if count >= 2:
        return True
    else:
        return False


def register():
    # we will ask for the username
    username = input("Introduce your username: ")
    # Use the previous function, to check if we dont have repeat usernames
    if find_user(username):
        print("Username already exists, choose other username")
        return

    passwordcondition = False
    while (passwordcondition == False):
        password = input("Introduce your password, it must have length longer than 8, atleast 2 special characters: ")
        if len(password) > 8 and special_check(password):
            # Now we need to encrypt the password using scrypt and store it along with username
            try:
                with open('users.json', 'r') as file:
                    data = json.load(file)
                max_id = max(user['id'] for user in data['users']) if data['users'] else 0
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
                key = kdf2.derive(password.encode('utf-8'))
                p_balance = str(0.0).encode('utf-8') 
                aesgcm = AESGCM(key)
                nonce = os.urandom(16) # Your original 16-byte nonce
                encrypted_balance = aesgcm.encrypt(nonce, p_balance, None)
                
                new_user = {
                    "id": next_id, 
                    "username": username,
                    "salt": salt.hex(), 
                    "password_hash": hashed_password.hex(), 
                    "key_salt": key_salt.hex(), 
                    "encrypted_balance": encrypted_balance.hex(), 
                    "bal_nonce": nonce.hex() 
                }


                data["users"].append(new_user)

                with open('users.json', 'w') as file:
                    json.dump(data, file, indent=4)
                print("Your registration was sucessful")
                passwordcondition = True 
                return True
            
            except FileNotFoundError:
                with open(DB_FILE, 'w') as file:
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
                    key = kdf2.derive(password.encode('utf-8'))
                    p_balance = str(0.0).encode('utf-8') 
                    aesgcm = AESGCM(key)
                    nonce = os.urandom(16)
                    encrypted_balance = aesgcm.encrypt(nonce, p_balance, None)
                    new_user = {
                        "id": 1, # First user
                        "username": username,
                        "salt": salt.hex(),
                        "password_hash": hashed_password.hex(),
                        "key_salt": key_salt.hex(),
                        "encrypted_balance": encrypted_balance.hex(),
                        "bal_nonce": nonce.hex() 
                    }
                    json.dump({"users": [new_user]}, file, indent=4)
                print("Your registration was successful!")
                passwordcondition = True
                return True # Kept your original return
        else:
            print("Password does not meet requirements, try again!")


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
            return (True, key)
        
        except InvalidKey: 
            print("Invalid username or password.")
            return (False, None) 
        except Exception:
            print("Invalid username or password.")
            return (False, None)

    else:
        print("Invalid username or password.")
        return (False, None)
