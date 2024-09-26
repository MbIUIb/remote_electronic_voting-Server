import os
import socket

import logging

import rsa
from dotenv import load_dotenv

from client_handler import ClientHandler

# env
load_dotenv()

# logs
logging.basicConfig(filename='remote_electronic_voting-Server.log',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    encoding="utf-8")

TYPE = socket.AF_INET
PROTOCOL = socket.SOCK_STREAM

# create and bind server socket
server_socket = socket.socket(TYPE, PROTOCOL)
server_socket.bind((os.getenv("SOCKET_HOST"), int(os.getenv("SOCKET_PORT"))))
server_socket.listen(100)

server_pubkey, server_privkey = rsa.newkeys(512)

client_handler_threads = []

# infinity sycle for clients connect
while True:
    conn, addr = server_socket.accept()
    logging.info(f"{addr} connected. Connection: {conn}")

    # client_handler = ClientHandler(f"Thread {addr[0]}_{addr[1]}", conn, server_pubkey, server_privkey)
    client_handler = ClientHandler(conn, server_pubkey, server_privkey)
    client_handler.start()

    client_handler_threads.append(client_handler)

    # очистка остановленных потоков
    for client_thread in client_handler_threads:
        if not client_thread.is_alive():
            client_handler_threads.remove(client_thread)

    print(client_handler_threads)
