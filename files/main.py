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
CA_CERT_FILE = 'ac1cert.pem' 

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

def decrypt_balance(user_data, rsa_private_key):
    try:
        # 1. Get the encrypted AES key from the DB
        enc_aes_key_hex = user_data.get("encrypted_aes_key")
        if not enc_aes_key_hex:
            print("Error: No encrypted key found.")
            return 0.0

        # 2. Decrypt the AES key using RSA 
        aes_key = pki.rsa_decrypt_key(rsa_private_key, enc_aes_key_hex)

        # 3. Decrypt the balance using the AES key
        nonce_hex = user_data["bal_nonce"]
        ciphertext_hex = user_data["encrypted_balance"]
        
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        aesgcm = AESGCM(aes_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return float(decrypted_bytes.decode('utf-8'))

    except InvalidTag:
        print("Integrity Check Failed: Balance corrupted.")
        return None
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def encrypt_balance(balance_float, user_cert):
    try:
        # 1. Generate a brand new random AES key (32 bytes)
        aes_key = os.urandom(32)

        # 2. Encrypt the balance with AES
        balance_bytes = str(balance_float).encode('utf-8')
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(16)
        ciphertext = aesgcm.encrypt(nonce, balance_bytes, None)

        # 3. Encrypt the AES key with the User's Public Key
        public_key = user_cert.public_key()
        encrypted_aes_key_hex = pki.rsa_encrypt_key(public_key, aes_key)

        return nonce.hex(), ciphertext.hex(), encrypted_aes_key_hex
    except Exception as e:
        print(f"Encryption error: {e}")
        return None, None, None

def update_user_in_db(username, new_nonce_hex, new_ciphertext_hex, new_enc_key_hex, new_signature_hex):
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
            user["encrypted_aes_key"] = new_enc_key_hex 
            user["last_balance_signature"] = new_signature_hex 
            user_found = True
            break
    if user_found:
        save_db(data)
    else:
        print(f"Error: Could not find user {username} to save balance.")

def main_menu():

    logged_in_user = None
    current_key = None      
    current_rsa_key = None  
    current_balance = None

    # In main.py
    try:
        ca_cert = pki.load_certificate_from_pem_file(CA_CERT_FILE)
        
        # Verify Self-Signed Integrity
        public_key = ca_cert.public_key()
        
        # We try to verify using the pki.py function first (Consistency)
        try:
            # We treat the CA as both the "Cert to verify" and the "Issuer"
            pki.verify_certificate_signature(ca_cert, public_key)
            print("Integrity Check: Root CA is valid and self-signed.")
        except Exception as e:
            print("FATAL: Root CA file is corrupted or forged!")
            exit()
            
    except FileNotFoundError:
        print(f"FATAL ERROR: CA certificate '{CA_CERT_FILE}' not found. The application cannot run.")
        return

    while True:
        if logged_in_user:
            print(f"\n--- Menu (Logged in as: {logged_in_user['username']}) ---")
            print(f"Current Balance: {current_balance}")
            print("---------------------------------------")
            print("1. Play Blackjack")
            print("2. Add Balance")
            print("3. Log out (Save & Exit)")
            print("---------------------------------------")
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                print("Starting Blackjack...")
                current_balance = play_blackjack_game(current_balance)

            elif choice == '2':
                try:
                    amount_str = input("Enter amount to add: ")
                    amount_to_add = float(amount_str)
                    
                    if amount_to_add > 0:
                        current_balance += amount_to_add
                        print(f"Successfully added {amount_to_add}.")
                        print(f"Your new balance is now: {current_balance}")
                    else:
                        print("Amount must be positive.")
                except ValueError:
                    print("Invalid amount. Please enter a number.")

            elif choice == '3':
                print(f"Saving balance for {logged_in_user['username']}...")

                # 1. Encrypt new balance using the certificate
                user_cert_obj = pki.load_certificate_from_pem_string(logged_in_user['user_certificate_pem'])
                new_nonce, new_ciphertext, new_enc_key = encrypt_balance(current_balance, user_cert_obj)

                # 2. Sign the new balance
                new_signature = None
                if new_nonce: 
                    try:
                        # We sign a combination of username and balance
                        message_to_sign = f"{logged_in_user['username']}:{current_balance}".encode('utf-8')
                        new_signature = pki.sign_data(current_rsa_key, message_to_sign)
                        print("New balance signed.")
                    except Exception as e:
                        print(f"Error signing data: {e}")

                # 3. Update database
                update_user_in_db(logged_in_user['username'], new_nonce, new_ciphertext, new_enc_key, new_signature)

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
                # Login returns three items
                user_data_from_login, key_from_login, rsa_key_from_login = login()

                if user_data_from_login:
                    print("Login successful. Verifying user certificate...")
                    try:
                        # Load the user's certificate from the DB
                        user_cert = pki.load_certificate_from_pem_string(user_data_from_login['user_certificate_pem'])
                        
                        # Verify the user's certificate is signed by the CA
                        is_user_cert_valid = pki.verify_certificate_signature(user_cert, ca_cert.public_key())

                        if is_user_cert_valid:
                            print("SUCCESS: User certificate is valid and signed by our CA.")
                            
                            logged_in_user = user_data_from_login
                            current_key = key_from_login
                            current_rsa_key = rsa_key_from_login
                            
                            # Decrypt balance
                            current_balance = decrypt_balance(logged_in_user, current_rsa_key)
                            
                            if current_balance is not None:
                                # verify signature
                                print("Verifying balance integrity...")
                                last_sig = logged_in_user.get("last_balance_signature")
                                
                                if last_sig is None:
                                    print("First login, no signature to verify. Welcome!")
                                else:
                                    # Extract the public key from the certificate
                                    user_public_key = user_cert.public_key()
                                    message_to_verify = f"{logged_in_user['username']}:{current_balance}".encode('utf-8')
                                    
                                    if pki.verify_signature(user_public_key, message_to_verify, last_sig):
                                        print("SUCCESS: Balance integrity verified.")
                                    else:
                                        print("WARNING: Balance signature is INVALID!!!")
                                        print("Your account data may have been tampered with")

                                print(f"Login successful. Your balance of {current_balance} has been loaded.")
                            else:
                                print("Login successful, but could not load balance. Logging out.")
                                logged_in_user = None

                        else:
                            print("ERROR: User certificate verification failed! It may be tamper with or not signed by our CA.")

                    except Exception as e:
                        print(f"An unexpected error occurred during certificate verification: {e}")
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
