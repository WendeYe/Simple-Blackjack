import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from blackjackLogic import *
from login import *

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

def update_user_in_db(username, new_nonce_hex, new_ciphertext_hex):
    if new_nonce_hex is None or new_ciphertext_hex is None:
        print("Could not update database due to encryption error.")
        return

    data = load_db()
    
    user_found = False
    for user in data["users"]:
        if user["username"] == username:
            user["bal_nonce"] = new_nonce_hex
            user["encrypted_balance"] = new_ciphertext_hex
            user_found = True
            break
    if user_found:
        save_db(data)
    else:
        print(f"Error: Could not find user {username} to save balance.")
        
def main_menu():
    
    logged_in_user = None
    current_key = None 
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
                # --- This is where you would call your game logic ---
                # Example: current_balance = play_game(current_balance)
                
                # For this demo, we'll just add 10 to the balance
                current_balance += 10
                print(f"You won 10! Your new balance is: {current_balance}")
            
            elif choice == '2':
                print(f"Your current balance is: {current_balance}")
            
            elif choice == '3':
                print(f"Saving balance for {logged_in_user['username']}...")
                
                new_nonce, new_ciphertext = encrypt_balance(current_balance, current_key)
                update_user_in_db(logged_in_user['username'], new_nonce, new_ciphertext)
                
                print(f"Logging out {logged_in_user['username']}...")
                logged_in_user = None
                current_key = None
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
                user_data_from_login, key_from_login = login() 
                
                if user_data_from_login:
                    logged_in_user = user_data_from_login
                    current_key = key_from_login
                    current_balance = decrypt_balance(logged_in_user, current_key)
                    
                    if current_balance is not None:
                        print(f"Login successful. Your balance of {current_balance} has been loaded.")
                    else:
                        print("Login successful, but could not load balance. Logging out.")
                        logged_in_user = None
                        current_key = None
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
  
