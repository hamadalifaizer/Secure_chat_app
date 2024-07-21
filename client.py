import socket
import json
import threading
import PySimpleGUI as sg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa 
from cryptography.hazmat.primitives import serialization
import base64
import os

def load_config():
    file_path = os.path.join(os.getcwd(), 'chatapp', 'setup.json')
    try:
        with open(file_path, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"Config file not found: {file_path}. Ensure that it is the correct path")
        return None

cfg = load_config()
SERVER_IP = cfg.get("server_ip")
SERVER_PORT = 5001
adres = {}

class ChatClient:
    def __init__(self):
        self.client_socket = None
        self.public_chat_history = []
        self.private_chat_history = {}
        self.online_users = []
        self.online_users_keys = {}
        self.keys = {}
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

        self.window = sg.Window("Chat Client", layout)
        self.generate_keys()
        self.connect_to_server()

    def send_public_message(self, text):
        if text == 'quit':
            self.on_closing()
            self.client_socket.sendall(b'')
            return
        print(text)
        data = json.dumps({'tag' : 'message', "from": self.username, "to": 'public', "info": text})
        self.client_socket.sendall(data.encode('utf-8'))

    def send_private_message(self, text, receiver):
        if text == 'quit':
            self.on_closing()
            return
        ciphertext = self.encrypt_message(text,receiver)
        data = json.dumps({"tag": "message", "from": self.username, "to": receiver, "info": ciphertext})
        self.client_socket.sendall(data.encode('utf-8'))

    def receive_message(self, stop_event):
        while not stop_event.is_set():
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if not message:
                    print("Connection closed by server.")
                    stop_event.set()
                    break
                data = json.loads(message)
                self.handle_message(data)
            except (json.JSONDecodeError, ConnectionResetError, ConnectionAbortedError) as e:
                print(f"Error receiving message: {e}")

    def handle_message(self, data):
        tag = data.get("tag")

        if tag == 'message':
            sender = data.get("from")
            target = data.get("to")
            encoded_text = data.get("info")

            if target == "public":
                self.public_chat_history.append(f"{sender}: {encoded_text}")
                self.window['-PUBLIC_CHAT-'].update("\n".join(self.public_chat_history))
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

    def on_closing(self):
        if self.client_socket:
            self.client_socket.close()
        self.window.close()

    def get_credentials(self):
        layout = [
            [sg.Text("Username:"), sg.InputText(key='-USERNAME-')],
            [sg.Text("Password:"), sg.InputText(key='-PASSWORD-', password_char='*')],
            [sg.Button("Submit"), sg.Button("Cancel")]
        ]
        window = sg.Window("Login", layout)
        event, values = window.read()
        window.close()
        return values['-USERNAME-'], values['-PASSWORD-']

    # Encrypt the message with public key
    def encrypt_message(self, message, target):
        print(f"\n\n\n\n target is {target}")
        # print(self.online_users_keys.keys())
        # Fetch the public key directly
        public_key = self.online_users_keys[target]
        print(f"pubkey is : \n{public_key}")
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)
        )
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        print(encoded_ciphertext)
        return encoded_ciphertext
    
    def decrypt_message(self, encoded_ciphertext):
        try:
            # bytes_ciphertext = str.encode(encoded_ciphertext)
            ciphertext = base64.b64decode(encoded_ciphertext.encode('utf-8'))
            private_key = self.keys["privkey"]
            decrypted_message = private_key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA256(), label=None)
            )
            return decrypted_message.decode()
        except:
            return('System Message : Failed to decrypt')

    # Generate RSA key and push to key dictionary
    def generate_keys(self):
        self.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_key = self.priv_key.public_key()
        self.keys["publickey"] = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.keys["privkey"] = self.priv_key

    # Authenticate user
    def authenticate(self):
        self.username, self.password = self.get_credentials()
        credentials = json.dumps({"username": self.username, "password": self.password, 'pubkey': self.keys["publickey"] }) 
        self.client_socket.sendall(credentials.encode('utf-8'))
        response = self.client_socket.recv(1024).decode('utf-8')
        print(response)
        return response

    def connect_to_server(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((SERVER_IP, SERVER_PORT))

        response = self.authenticate()

        if "Authenticated successfully" not in response:
            sg.popup_error("Authentication Failed", "Invalid credentials, please try again.")
            self.authenticate()

        stop_event = threading.Event()
        receive_thread = threading.Thread(target=self.receive_message, args=(stop_event,))
        receive_thread.start()

        try:
            receiver=''
            while True:
                event, values = self.window.read()
                if event == '-USER_LIST-':
                    selected_user = self.window['-USER_LIST-'].get()
                    receiver = ''.join(selected_user)[1::-2]
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
                    receiver = self.window['-USER_LIST-'].get()
                    # receiver = ''.join(selected_user)
                    print(receiver)
                    if receiver:
                        self.send_private_message(message, receiver[0])
                        if receiver[0] not in self.private_chat_history:
                            print(receiver[0])
                            self.private_chat_history[receiver[0]] = []
                        self.private_chat_history[receiver[0]].append(f"{self.username}: {message}")
                        print(receiver[0])
                        self.window['-PRIVATE_CHAT-'].update("\n".join(self.private_chat_history[receiver[0]]))
                    self.window['-PRIVATE_MESSAGE-'].update('')  # Clear input box
        except Exception as e:
            print(f"Error {e}")

if __name__ == "__main__":
    client = ChatClient()
