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

def main_menu():
    
    logged_in_user = None
    current_key = None 

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
                # to add
            
            elif choice == '2':
                print("Checking balance...")
                balance = decrypt_balance(logged_in_user, current_key)
                if balance is not None:
                    print(f"Your current balance is: {balance}")
                else:
                    print("Could not retrieve balance.")
            
            elif choice == '3':
                print(f"Logging out {logged_in_user['username']}...")
                logged_in_user = None
                current_key = None
            
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
  
