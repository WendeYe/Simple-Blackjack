# Implementation of a login function, that is also in charge of the creation of accounts
import os
import scrypt
import json

def find_user(usertofind):
    # check the json database we have for the existence of the username

    try:
        with open('users.json', 'r') as file:
            data = json.load(file)
            userlist = data.get('users', []) # if users doesn't exist .get would return none i think
            for user in userlist:
                if userlist['username'] == usertofind:
                    return user

            return None


    except FileNotFoundError:
        print("Error, the JSON file was not found")
        return None


#The creation of the register function, we will store the usernames in plaintext

def special_check(password):
    special_characters = "!@#$%^&*()_-+={[}]|\:;'<,>.?/"
    count = 0
    for char in password:
        if char in special_characters:
            count += 1
    if count > 2:
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
            with open('users.json', 'r') as file:
                data = json.load(file)
            max_id = max(user['id'] for user in data['users'])
            next_id = max_id + 1
            # generated a salt of 32 bytes
            salt = os.urandom(32)
            hashed_password = scrypt.hash(password.encode('utf-8'), salt,16384,8,1) # https://cryptobook.nakov.com/mac-and-key-derivation/scrypt, used parameters found on this website
            new_user = {
                "id": next_id,
                "username": username,
                "salt": salt.hex(),
                "password_hash": hashed_password.hex()
            }


            with open('users.json', 'r') as file:
                data = json.load(file)

            data["users"].append(new_user)

            with open('users.json','w') as file:
                json.dump(data, file,indent=4)

            print("Your registration was sucessful")
            return True
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

            #as we stored it in hax, we need to convert it to bytes

            salt = bytes.fromhex(salt_hex)
            hash = bytes.fromhex(hash_hex)
            rehashed_password = scrypt.hash(password.encode('utf-8'), salt, 16384, 8, 1)

            if hash == rehashed_password:
                print(f"Verified user, welcome {username}")
                return True
            else:
                print("Invalid combination, username/password")
                return False

            # now we recalculate the hash using the salt and we compare them

        else:
            print("Username/Password does not exist")
            return False
