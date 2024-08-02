import socket

import logging

from client_handler import ClientHandler

# logs
logging.basicConfig(filename='remote_electronic_voting-Server.log',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    encoding="utf-8")

HOST = ''
PORT = 9999
TYPE = socket.AF_INET
PROTOCOL = socket.SOCK_STREAM

# create and bind server socket
server_socket = socket.socket(TYPE, PROTOCOL)
server_socket.bind((HOST, PORT))
server_socket.listen(100)

client_handler_threads = []

# infinity sycle for clients connect
while True:
    conn, addr = server_socket.accept()
    logging.info(f"{addr} connected. Connection: {conn}")

    client_handler_threads.append(ClientHandler(f"Thread {addr[0]}", conn).start())
