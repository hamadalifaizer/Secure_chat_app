import socket
import json
import threading
import PySimpleGUI as sg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import base64
import os
import sys
import hashlib

def load_config():
    file_path = os.path.join(os.getcwd(), 'client_setup.json')
    try:
        with open(file_path, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"Config file not found: {file_path}. Ensure that it is the correct path")
        return None

cfg = load_config()
print(cfg)
SERVER_IP = cfg.get("server_ip")
SERVER_PORT = 5001

class ChatClient:
    def __init__(self):
        self.client_socket = None
        self.username = None
        self.public_chat_history = []
        self.private_chat_history = {}
        self.online_users = []
        self.online_users_keys = {}
        self.keys = {}
        self.server_keys={}
        self.stop_event = threading.Event()

        self.window = None
        self.login_window = None
        self.receive_thread = None
        
        self.connect_to_server()  # Establish server connection first
        self.generate_keys()      # Generate keys before login
        self.create_login_window()
        self.handle_login()

    def create_login_window(self):
        layout = [
            [sg.Text("Username:"), sg.InputText(key='-USERNAME-')],
            [sg.Text("Password:"), sg.InputText(key='-PASSWORD-', password_char='*')],
            [sg.Button("Submit"), sg.Button("Cancel")]
        ]
        self.login_window = sg.Window("Login", layout, finalize=True)

    def create_main_window(self):
        layout = [
            [
                sg.Frame("Public Chat", [
                    [sg.Multiline(size=(50, 20), key='-PUBLIC_CHAT-', disabled=True)],
                    [sg.Input(size=(40, 1), key='-PUBLIC_MESSAGE-'), sg.Button('Send Public')]
                ]),
                sg.Frame("Private Chat", [
                    [sg.Listbox(values=[], size=(30, 15), key='-USER_LIST-', enable_events=True, select_mode=sg.LISTBOX_SELECT_MODE_SINGLE)],
                    [sg.Multiline(size=(50, 20), key='-PRIVATE_CHAT-', disabled=True)],
                    [sg.Input(size=(40, 1), key='-PRIVATE_MESSAGE-'), sg.Button('Send Private')]
                ])
            ]
        ]

        self.window = sg.Window("Chat Client", layout, finalize=True)
    
    def hash_password(self):
        return hashlib.sha256(self.password.encode()).hexdigest()
    
    def authenticate(self):
        if self.username and self.password:
            self.hashed_password = self.hash_password()
            self.encrypted_password=self.encrypt_password(self.hashed_password)
            credentials = json.dumps({"username": self.username, "password": self.encrypted_password, 'pubkey': self.keys.get("publickey")})
            if not self.keys.get("publickey"):
                sg.popup_error("Key Error", "Public key is missing. Please restart the application.")
                self.on_closing()
                return
            self.client_socket.sendall(credentials.encode('utf-8'))
            response = self.client_socket.recv(4096).decode('utf-8')
            if "Authenticated successfully" in response:
                self.login_window.close()
                self.create_main_window()
                self.start_main_loop()
            else:
                sg.popup_error("Authentication Failed", "Invalid credentials, please try again.")
    


    def send_public_message(self, text):
        if text == 'quit':
            self.on_closing()
            self.client_socket.sendall(b'')
            return
        print(text)
        data = json.dumps({'tag': 'message', "from": self.username, "to": 'public', "info": text})
        self.client_socket.sendall(data.encode('utf-8'))

    def send_private_message(self, text, receiver):
        if text == 'quit':
            self.on_closing()
            return
        ciphertext = self.encrypt_message(text, receiver)
        data = json.dumps({"tag": "message", "from": self.username, "to": receiver, "info": ciphertext})
        self.client_socket.sendall(data.encode('utf-8'))

    def receive_message(self):
        while not self.stop_event.is_set():
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if not message:
                    print("Connection closed by server.")
                    self.stop_event.set()
                    break
                data = json.loads(message)
                self.handle_message(data)
            except (json.JSONDecodeError, ConnectionResetError, ConnectionAbortedError) as e:
                print(f"Error receiving message: {e}")

    def handle_message(self, data):
        try:
            tag = data.get("tag")

            if tag == 'message':
                sender = data.get("from")
                target = data.get("to")
                encoded_text = data.get("info")

                if target == "public":
                    self.public_chat_history.append(f"{sender}: {encoded_text}")
                    self.window['-PUBLIC_CHAT-'].update("\n".join(self.public_chat_history))
                    return
                else:
                    if sender not in self.private_chat_history:
                        self.private_chat_history[sender] = []
                    text = self.decrypt_message(encoded_text)
                    self.private_chat_history[sender].append(f"{sender}: {text}")
                    self.window['-PRIVATE_CHAT-'].update("\n".join(self.private_chat_history.get(sender, [])))

            elif tag == "onlinelist":
                self.online_data = data.get("data")
                self.online_users = []
                for x in self.online_data:
                    if not x == self.username:
                        self.online_users.append(x)
                        # Store public key directly
                        public_key_pem = self.online_data[x]["publickey"]
                        self.online_users_keys[x] = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
                self.window['-USER_LIST-'].update(values=self.online_users)
        except Exception as e:
            print(f"Failed to handle the message: {e}")

    def on_closing(self):
        if self.client_socket:
            self.client_socket.close()
        if self.window:
            self.window.close()
        if self.login_window:
            self.login_window.close()
        sys.exit()

    def encrypt_password(self, password):
        pubkey = serialization.load_pem_public_key(self.server_keys['pubkey'].encode('utf-8'))
        ciphertext = pubkey.encrypt(
            password.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)
        )
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        return encoded_ciphertext
    
    def encrypt_message(self, message, target):
        print(f"Encrypt_message: Encrypting {message} with {target} PubKey")
        public_key = self.online_users_keys[target]
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)
        )
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        return encoded_ciphertext

    def decrypt_message(self, encoded_ciphertext):
        try:
            ciphertext = base64.b64decode(encoded_ciphertext.encode('utf-8'))
            private_key = self.keys["privkey"]
            decrypted_message = private_key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)
            )
            return decrypted_message.decode()
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return 'System Message: Failed to decrypt'

    def generate_keys(self):
        self.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_key = self.priv_key.public_key()
        self.keys["publickey"] = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.keys["privkey"] = self.priv_key

    def handle_login(self):
        while True:
            event, values = self.login_window.read()
            if event == sg.WIN_CLOSED or event == 'Cancel':
                self.on_closing()
                break
            if event == 'Submit':
                self.username = values['-USERNAME-']
                self.password = values['-PASSWORD-']
                self.authenticate()  # Call authenticate method here
                break

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_IP, SERVER_PORT))
            self.client_socket.sendall("reqpub".encode('utf-8'))
            response_data = self.client_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            if response['tag'] == 'server_pubkey':
                self.server_keys['pubkey'] = response['pubkey']
                print(f"Received Server Public Key")
            else:
                print("Unexpected response from server.")
        except Exception as e:
            sg.popup_error("Connection Error", f"Could not connect to server: {e}")
            sys.exit()

    def start_main_loop(self):
        self.stop_event.clear()
        self.receive_thread = threading.Thread(target=self.receive_message)
        self.receive_thread.start()

        try:
            receiver = ''
            while True:
                event, values = self.window.read()
                if event == '-USER_LIST-':
                    selected_user = self.window['-USER_LIST-'].get()
                    receiver = ''.join(selected_user)
                    if selected_user:
                        self.window['-PRIVATE_CHAT-'].update("\n".join(self.private_chat_history.get(selected_user[0], [])))
                if event == sg.WIN_CLOSED:
                    self.on_closing()
                    break
                elif event == 'Send Public':
                    message = values['-PUBLIC_MESSAGE-']
                    self.send_public_message(message)
                    self.window['-PUBLIC_MESSAGE-'].update('')  # Clear input box
                elif event == 'Send Private':
                    message = values['-PRIVATE_MESSAGE-']
                    if receiver:
                        self.send_private_message(message, receiver)
                        if receiver not in self.private_chat_history:
                            self.private_chat_history[receiver] = []
                        self.private_chat_history[receiver].append(f"{self.username}: {message}")
                        self.window['-PRIVATE_CHAT-'].update("\n".join(self.private_chat_history[receiver]))
                    self.window['-PRIVATE_MESSAGE-'].update('')  # Clear input box
        except Exception as e:
            print(f"Error: {e}")
            self.on_closing()

if __name__ == "__main__":
    ChatClient()
