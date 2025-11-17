import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from blackjackLogic import play_blackjack_game
from login import login, register
import pki

DB_FILE = 'users.json'

def load_db():
    try:
        with open(DB_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {"users": []}
    except json.JSONDecodeError:
        print("Error: users.json is corrupted. Creating a new one.")
        return {"users": []}

def save_db(data):
    with open(DB_FILE, 'w') as file:
        json.dump(data, file, indent=4)

def decrypt_balance(user_data, password_derived_key):
    try:
        nonce_hex = user_data["bal_nonce"]
        ciphertext_hex = user_data["encrypted_balance"]
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        aesgcm = AESGCM(password_derived_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        decrypted_balance_str = decrypted_bytes.decode('utf-8')
        return float(decrypted_balance_str)

    except InvalidTag:
        print("Decryption failed! This should not happen if login succeeded.")
        return None
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None

def encrypt_balance(balance_float, password_derived_key):
    try:
        balance_bytes = str(balance_float).encode('utf-8')
        aesgcm = AESGCM(password_derived_key)
        new_nonce = os.urandom(16)
        new_ciphertext = aesgcm.encrypt(new_nonce, balance_bytes, None)
    
        return new_nonce.hex(), new_ciphertext.hex()
    except Exception as e:
        print(f"Error occurred during encryption: {e}")
        return None, None

def update_user_in_db(username, new_nonce_hex, new_ciphertext_hex, new_signature_hex):
    if new_nonce_hex is None or new_ciphertext_hex is None:
        print("Could not update database due to encryption error.")
        return
    if new_signature_hex is None:
        print("Could not update database due to signing error.")
        return

    data = load_db()
    
    user_found = False
    for user in data["users"]:
        if user["username"] == username:
            user["bal_nonce"] = new_nonce_hex
            user["encrypted_balance"] = new_ciphertext_hex
            user["last_balance_signature"] = new_signature_hex # Save the new signature
            user_found = True
            break
    if user_found:
        save_db(data)
    else:
        print(f"Error: Could not find user {username} to save balance.")
        
def main_menu():
    
    logged_in_user = None
    current_key = None      # AES key for balance
    current_rsa_key = None  # RSA key for signing
    current_balance = None

    while True:
        if logged_in_user:
            print(f"\n--- Menu (Logged in as: {logged_in_user['username']}) ---")
            print("1. Play Blackjack")
            print("2. Check Balance")
            print("3. Logout")
            print("---------------------------------------")
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                print("Starting Blackjack...")
                current_balance = play_blackjack_game(current_balance)
                
            elif choice == '2':
                print(f"Your current balance is: {current_balance}")
            
            elif choice == '3':
                print(f"Saving balance for {logged_in_user['username']}...")
                
                # 1. Encrypt new balance
                new_nonce, new_ciphertext = encrypt_balance(current_balance, current_key)
                
                # 2. Sign the new balance
                new_signature = None
                if new_nonce: # Only sign if encryption succeeded
                    try:
                        # We sign a combination of username and balance
                        message_to_sign = f"{logged_in_user['username']}:{current_balance}".encode('utf-8')
                        new_signature = pki.sign_data(current_rsa_key, message_to_sign)
                        print("New balance signed.")
                    except Exception as e:
                        print(f"Error signing data: {e}")

                # 3. Update database with new data and signature
                update_user_in_db(logged_in_user['username'], new_nonce, new_ciphertext, new_signature)
                
                print(f"Logging out {logged_in_user['username']}...")
                logged_in_user = None
                current_key = None
                current_rsa_key = None
                current_balance = None
            
            else:
                print("Invalid choice.")
                
        else:
            
            print("\n--- Welcome to Blackjack ---")
            print("1. Login")
            print("2. Register")
            print("q. Quit")
            print("----------------------------")
            
            choice = input("Please enter your choice (1, 2, or q): ").strip().lower()

            if choice == '1':
                # Login now returns THREE items
                user_data_from_login, key_from_login, rsa_key_from_login = login() 
                
                if user_data_from_login:
                    logged_in_user = user_data_from_login
                    current_key = key_from_login
                    current_rsa_key = rsa_key_from_login
                    
                    # Decrypt balance as before
                    current_balance = decrypt_balance(logged_in_user, current_key)
                    
                    if current_balance is not None:
                        # # verify signature
                        print("Verifying balance integrity...")
                        last_sig = logged_in_user.get("last_balance_signature") # .get avoids error if key missing
                        
                        if last_sig is None:
                            print("First login, no signature to verify. Welcome!")
                        else:
                            try:
                                pem_public = logged_in_user['rsa_public_key_pem']
                                public_key = pki.load_public_key(pem_public)
                                message_to_verify = f"{logged_in_user['username']}:{current_balance}".encode('utf-8')
                                
                                if pki.verify_signature(public_key, message_to_verify, last_sig):
                                    print("SUCCESS: Balance integrity verified.")
                                else:
                                    print("WARNING: Balance signature is INVALID!!!")
                                    print("Your account data may have been tampered with")
                            except Exception as e:
                                print(f"Could not verify signature: {e}")

                        print(f"Login successful. Your balance of {current_balance} has been loaded.")
                        
                    else:
                        print("Login successful, but could not load balance. Logging out.")
                        logged_in_user = None
                        current_key = None
                        current_rsa_key = None
                else:
                    print("Login failed. Please try again.")
                    

            elif choice == '2':
                register()

            elif choice == 'q':
                print("Goodbye!")
                break 
                
            else:
                print("Invalid choice. Please select 1, 2, or q.")

if __name__ == "__main__":
    main_menu()
