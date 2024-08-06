import os
import json
import hashlib
import getpass

print("Account Register. . .")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register(username, password):
    file_path = os.path.join(os.getcwd(), 'setup.json')
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                data = json.load(file)
        else:
            data = {"admin": {}}

        if username in data['admin']:
            print(f"Username: {username} already exists")
            return
        else:
            data['admin'][username] = hash_password(password)
        
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=4)
        print("Registration successful")

    except FileNotFoundError:
        print(f"Config file not found: {file_path}. Ensure that it is the correct path")
    except json.JSONDecodeError:
        print(f"Error decoding JSON from file: {file_path}")
    except IOError as e:
        print(f"IO Error: {e}")

def main():
    while True:
        username = input("Please input username [A-Z,a-z,0-9](or 'q' to quit): ")
        if username == 'q':
            print("Closing Account Register")
            return

        if not username.isalnum():
            print("Invalid Username: please only include A-Z, a-z, 0-9")
            continue

<<<<<<< HEAD
        if  len(username)<=1:
=======
        if  len(username)<=1 or len(username) >= 8:
>>>>>>> 54f277f5c7c14cc806deebd7cc8d7976b5b2312c
            print("Invalid Username: Length must be more than 1")
            continue

        password1 = getpass.getpass("Please input password: ")
        password2 = getpass.getpass("Please re-input password: ")

        if password1 == password2:
            if '@server3' not in username:
                username += '@server3'
            register(username, password1)
        else:
            print("Password mismatch. Please reenter.")

if __name__ == "__main__":
    main()
