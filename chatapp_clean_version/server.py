import asyncio
import websockets
import json
import socket
import threading
import os

    
    
def load_config():
    file_path = os.path.join(os.getcwd(), 'setup.json')
    try:
        with open(file_path, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"Config file not found: {file_path}. Ensure that it is the correct path")
        return None

config = load_config()
SERVER_NAME = config.get("server_name")  
SERVER_IP = config.get("server_ip")  
ADMIN = config.get("admin")
MAILING_ADDRESS = config.get("mailing_address", {})
mailing_pubkey = {}
connected_clients = {}
clients_pubkey = {}
connected_servers = {}
presence_list = []
server_check = {}
adress_book = {}


def mailingip():
    ppp=[]
    for k,v in MAILING_ADDRESS.items():
        ppp.append(v.split(':')[0])
        server_check[k] = 'uncheck'
    return ppp

KNOWN_ADDRESS = mailingip()

async def broadcast(tag='message',text='', sender=SERVER_NAME):
    if tag == 'message':
        try :
            for target_socket in connected_clients.values():
                target_socket.sendall(json.dumps({'tag': tag, 'from': sender, 'to': 'public', 'info': text}).encode('utf-8'))
                print(f"Message sent to {target_socket} ")
            for target in MAILING_ADDRESS.keys():
                async with websockets.connect(f"wss://{MAILING_ADDRESS[target]}") as websocket:
                    await websocket.send(json.dumps({'tag': tag, 'from': sender, 'to': 'public', 'info': text}))
            print(f"Broadcast Success Message sent to Server's ")
        except Exception as e:
             print(f"Error at Broadcasting Message : {e}")

    elif tag == 'presence':
        try :
            for target in MAILING_ADDRESS.keys():
                async with websockets.connect(f"wss://{MAILING_ADDRESS[target]}") as websocket:
                            onlineclient = share_contact() 
                            await websocket.send(json.dumps({'tag': 'presence', 'presence': onlineclient}))
                            print(f"Broadcast Sucess : Broadcasted Presence to {target}")
        except Exception as e:
            print(f"Broadcast Failed : Failed to Broadcast Presence to Servers  {e}")

    elif tag == 'attendance':
        try:
            for target in MAILING_ADDRESS.keys():
                async with websockets.connect(f"wss://{MAILING_ADDRESS[target]}") as websocket:
                    await websocket.send(json.dumps({'tag': 'attendance'}))
                    print(f"Broadcast Sucess : Broadcasted Attendance Request")
                    
        except Exception as e:
            print(f"Broadcast Failed : Failed to Broadcast Attendace to Server  {e}")


def share_contact():
    presence_list.clear()
    for client in connected_clients.keys():
        presence_list.append({'nickname': client, 'jid': client, 'publickey': clients_pubkey[client]})
    return presence_list

def check_admin(username, password):
    return ADMIN.get(username) == password

def handle_client(client_socket, client_address):
    try:
        initial_message = client_socket.recv(4096).decode('utf-8')
        credentials = json.loads(initial_message)
        username = credentials.get("username")
        password = credentials.get("password")

        if not check_admin(username, password):
            print(f"Error: Invalid admin credentials : {username, password}")
            client_socket.sendall(b"Error: Invalid admin credentials")
            client_socket.close()
            return

        if username in connected_clients:
            print(f"Error: Admin already connected : {username} is already connected")
            client_socket.sendall(b"Error: Admin already connected")
            client_socket.close()
            return

        print(f"Succesfull Admin Authentication : Admin connection established from : {client_address}")
        connected_clients[username] = client_socket
        clients_pubkey[username] = credentials.get("pubkey")

        client_socket.sendall(b"Authenticated successfully")
        asyncio.run(broadcast(tag='presence'))
        print(f"Broadcasting New Presence to All Server : Client Connection Established from : {username}")
        asyncio.run(broadcast(tag='attendance'))

        while True:
            message = client_socket.recv(4096).decode('utf-8')
            if not message:
                print(message)
                print("INVALID MESSAGE")
                break

            data = json.loads(message)
            tag = data['tag']
            
            if tag == 'message':
                print("Received Message From Client")
                sender = data['from']
                receiver = data['to']                
                text = data['info']
                response = f"Client Handle-Server : will Sending {tag} from {sender} to {receiver}"
                print(response)
                client_socket.sendall(response.encode('utf-8'))

                if receiver == 'public':
                    asyncio.run(broadcast(tag='message',text=text, sender=sender))
                    break
                elif receiver in connected_clients:
                    target_socket = connected_clients[receiver]
                    print(f"SENDING TO {receiver}, {target_socket}")
                    target_socket.sendall(json.dumps({'tag': tag, 'from': sender, 'to': receiver, 'info': text}).encode('utf-8'))
                elif receiver.split('@')[1] in MAILING_ADDRESS:
                    asyncio.run(send_to_server(sender, receiver, text))
                else:
                    print(f"Failed to send Message : {receiver} not found in connected_clients or MAILING_ADDRESS")
                    client_socket.sendall(f"Error: Receiver {receiver} not found".encode('utf-8'))
  
            elif tag == 'file':
                sender = data['from']
                receiver = data['to']
                filename = data['filename']
                text = data['info']
                asyncio.run(send_to_server(sender, receiver, text, filename=filename, tag='file'))

    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error : Invalid JSON received or missing username/password {e}")
    
    finally:
        if username in connected_clients:
            tmp1=username
            del connected_clients[username]
            print(f"Client Disconnect : {tmp1} Is Disconnected : Broadcasting new presence list ")
        asyncio.run(broadcast(tag='presence'))
        client_socket.close()
        
async def server_handler(websocket, path=''):
    print("Received a Message : Attempt to validate message")
    remote_address = f"{websocket.remote_address[0]}"

    if remote_address in KNOWN_ADDRESS:
        print(f"{remote_address} is valid at known_address : Handling the message")
        connected_servers[remote_address] = websocket

    else:
        print(f"{remote_address} is not valid or registered at known_address : Breaking . . .")
        await websocket.close()
        return

    try:
        async for message in websocket:
            try:
                print(f"Received Message from {remote_address} : Unpacking Tag ")
                data = json.loads(message)
                tag = data['tag']
                print(f"Received Tag : {tag}")
                if tag == "presence":
                    for x,y in MAILING_ADDRESS.items():
                        y1 = y.split(':')[0]
                        if y1 == remote_address:
                            print(f"Received {x} Presence")
                            sender = x

                    if sender:
                        print(f"Unpacking presence from : {sender} ")
                        predata = data['presence']

                        if sender in adress_book:
                            print(f"Refreshing {sender} Adress_book")
                            del adress_book[sender]
                        adress_book[sender] = {}

                        for entry in predata:
                            jid = entry['jid']
                            publickey = entry['publickey']
                            adress_book[sender][jid] = {'publickey': publickey, 'status': 'online'}

                elif tag == 'attendance':
                    print(f"Received attendance request from {websocket.remote_address[0]}")
                    async with websockets.connect(f"wss://{websocket.remote_address[0]}:5555") as target_socket:
                        onlineclient = share_contact() 
                        await target_socket.send(json.dumps({'tag': 'presence', 'presence': onlineclient}))
                        print(f"Presence send via websocket\n\n{onlineclient}")

                elif tag == 'file':
                    sender = data['from']
                    receiver = data['to']
                    filename = data['filename']
                    text = data['info'] #BINARY DATA
                    if receiver in connected_clients:
                        target_socket = connected_clients[receiver]
                        print(f"Sending message from {sender} to {receiver} via socket")
                        target_socket.sendall(json.dumps({'from': sender, 'to': receiver, 'filename': filename, 'info': text}).encode('utf-8'))
                        print(f"File delivered to {receiver} via socket")
                    elif receiver == 'public':
                        for target_socket in connected_clients.values():
                            target_socket.sendall(json.dumps({'from': sender, 'to': receiver, 'filename': filename, 'info': text}).encode('utf-8'))
                            print(f"File delivered to {receiver} via socket")

                elif tag == "message":
                    sender = data['from']
                    receiver = data['to']
                    text = data['info']
                    if receiver in connected_clients:
                        target_socket = connected_clients[receiver]
                        print(target_socket)
                        target_socket.sendall(json.dumps({'tag':tag,'from': sender, 'to': receiver, 'info': text}).encode('utf-8'))
                        print(f"Message delivered to {receiver} via socket")

                    elif receiver == 'public':
                        for target_socket in connected_clients.values():
                            target_socket.sendall(json.dumps({'tag':tag,'from': sender, 'to': receiver, 'info': text}).encode('utf-8'))
                            print(f"Public Message delivered to {receiver} via socket")
                    else:
                        print(f"Receiver {receiver} not found")
                
                else:
                    await websocket.send("Invalid Tag")
                    print("Tag is Invalid : Message Rejected")
            except json.JSONDecodeError:
                print(f"Received invalid JSON: {message}")
                await websocket.send("Error: Invalid JSON received")
            except KeyError as e:
                print(f"Missing key in JSON data: {e}")
                await websocket.send(f"Error: Missing key in JSON data: {e}")
    except websockets.ConnectionClosed as e:
        print(f"Websockets Connection closed from : {e}")
    finally:
        connected_servers.pop(remote_address, None)

async def send_to_server(sender, receiver, text, filename=None, tag='message'):
    print("Sending Message to server via websocket")
    target = receiver.split('@')[1]
    if target in MAILING_ADDRESS:
        attempt = 0
        connected = False
        while attempt < 3 and not connected:
            try:
                async with websockets.connect(f"wss://{MAILING_ADDRESS[target]}") as websocket:
                    connected = True
                    print(f"Connected to known address: {target}")
                    if tag == 'message':
                        await websocket.send(json.dumps({'tag': tag, 'from': sender, 'to': receiver, 'info': text}))
                    elif tag == 'file':
                        await websocket.send(json.dumps({'tag': tag, 'from': sender, 'to': receiver, 'filename': filename, 'info': text}))
                    print(f"{tag} was send via websocket to {target}")
            except Exception as e:
                attempt += 1
                print(f"Attempt number {attempt} // Failed to connect to {receiver}: {e}")
                await asyncio.sleep(5)
        if not connected:
            print(f"Failed to connect to {target} after 3 attempts\nMessage Not Sent")
    else:
        print("Target not inside mailing address")

async def check_alive_clients():
    while True:
        for username, client_socket in list(connected_clients.items()):
            try:
                client_socket.sendall(b'\x00') #Sending to check if client is online
            except (ConnectionResetError, BrokenPipeError):
                del connected_clients[username]
                print(f"Client {username} removed due to no response")
                await broadcast(tag='presence')
        await asyncio.sleep(5)

async def check_alive_server():
    while True:
        for target in MAILING_ADDRESS.keys():
            attempt = 0
            connected = False
            while attempt < 3 and not connected and server_check[target] == 'uncheck':
                try:
                    async with websockets.connect(f"wss://{MAILING_ADDRESS[target]}") as websocket:
                        connected = True
                        print(f"Connected to known address: {target}")
                        await websocket.send(json.dumps({'tag': 'attendance'}))
                        if websocket.recv():
                            await server_handler(websocket)
                        print(f"Presence request to {target} : Server is now Checked")
                        server_check[target] = 'checked'
                        await asyncio.sleep(3)      
                except Exception as e:
                    attempt += 1
                    print(f"Attempt to connect to {target} : Attempt {attempt} : {e} ")
                    await asyncio.sleep(5)
            if not connected:
                print(f"Failed to connect to {target} after 3 attempts")
                if target in adress_book:
                    print("Refreshing")
                    del adress_book[target]
        
def socket_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, 5001))
    server_socket.listen(5)
    print(f"Socket server running on {SERVER_IP}:5001")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

async def online_users():
    while True:
        onlinebook = {}
        online_message=[]
        onlinebook.clear()
        for server, clients in adress_book.items():
            for client, details in clients.items():
                if details['status'] == 'online':
                    onlinebook[client] = {
                        'publickey': details['publickey'],
                        'status': details['status']
                    }
        share_contact()
        for clients in presence_list:
            onlinebook[clients['jid']] = {
                    'publickey': clients['publickey'],
                    'status': 'online'
                }
        online_message = json.dumps({'tag': 'onlinelist', 'data': onlinebook})        
        for target_socket in connected_clients.values():
            target_socket.send(online_message.encode('utf-8'))
        await asyncio.sleep(2)

        
async def main():
    try:
        print(f"Chat App v.1.0 Application Starting...")
        websocket_server = websockets.serve(server_handler, SERVER_IP, 5555) 
        await broadcast(tag='attendance')
        print("Broadcasted Alive to Servers : Send Attendace to every known server")
        await asyncio.gather(
            websocket_server,
            check_alive_clients(),
            check_alive_server(),
            online_users()
        )
    except Exception as e:
        print(f"Main Failure : {e}")

print(f"WebSocket server is running on ws://{SERVER_IP}:5555")
socket_thread = threading.Thread(target=socket_server)
socket_thread.start()
asyncio.run(main())
