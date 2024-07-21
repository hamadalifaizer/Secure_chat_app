# Chat App

# WARNING
## MALICIOUS FILE INTENTED FOR EDUCATIONAL PURPOSES

## Description
A secure chat system utilizing a standardized protocol (WebSockets). This application ensures secure and private communication between users with features like public and private messaging, user authentication, and message encryption.

## Features
- **Public and Private Messaging:** Users can send messages to the public chat or privately to specific users.
- **User Authentication:** Only authenticated users can connect and communicate.
- **Message Encryption:** Messages are encrypted using RSA to ensure privacy and security.
- **User Presence:** See the list of online users and their public keys.
- **Server Communication:** Communicate with other servers for broader connectivity using WebSockets and sockets.

## Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/hamadalifaizer/Secure_chat_app.git
    cd Secure_chat_app
    ```

2. **Install Dependencies:**
    - Ensure you have Python 3.x installed.
    - Install the required Python packages:
      ```bash
      pip install -r requirements.txt
      ```

3. **Configuration:**
    - **Server Setup:**
      Edit the `setup.json` file to include your server name, admin credentials, and mailing addresses. This file is used by the server to manage connections and communications.
      ```json
      {
          "server_name": "s3",
          "admin": {
              "client1@s3": "admin1",
              "client2@s3": "admin2",
              "client3@s3": "admin3",
              "client4@s3": "admin4"
          },
          "mailing_address": {
              "s8": "10.13.97.12:5555",
              "s4": "10.13.101.145:5555",
              "s1": "10.13.84.131:5555"
          }
      }
      ```
      - `server_name`: The name of your server.
      - `admin`: A dictionary mapping usernames to their respective passwords.
      - `mailing_address`: Addresses of other servers for inter-server communication.

    - **Client Setup:**
      Edit the `client_setup.json` file to specify the server IP address. This file is used by the client to connect to the server.
      ```json
      {
          "server_ip": "your.server.ip.address"
      }
      ```
      - `server_ip`: The IP address of the server to which the client should connect.

4. **Run the Server:**
    ```bash
    python server.py
    ```

5. **Run the Client:**
    ```bash
    python client.py
    ```

## Usage

1. **Start the Server:**
    - Ensure the server is configured correctly and run `server.py`.
    - The server will start listening on the specified IP and port.

2. **Start the Client:**
    - Run `client.py`.
    - Enter your username and password to authenticate.

3. **Public Chat:**
    - Send messages to the public chat visible to all users.

4. **Private Chat:**
    - Select a user from the list to start a private chat.

## Communication Protocols

- **WebSockets for Inter-Server Communication:** The servers use WebSockets to communicate with each other. This allows for asynchronous communication and ensures that messages can be relayed between different servers efficiently.
- **Sockets for Intra-Server Communication:** Within the server, sockets are used for communication between clients and the server. This allows for real-time message delivery and user presence updates.

## Authors
- Hamad Ali Faizer 
- Maxwell Pratama Kusuma Wirawan  
- Abdulkareem Okadigbo 
- Wei Kit Tan 
