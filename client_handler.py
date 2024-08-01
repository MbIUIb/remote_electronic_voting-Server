import json
import logging
import os
import socket
from threading import Thread

import requests
from dotenv import load_dotenv

# env
load_dotenv()

# logs
logging.basicConfig(filename='remote_electronic_voting-Server.log',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    encoding="utf-8")


class ClientHandler(Thread):
    def __init__(self, name, client_socket: socket.SocketType):
        Thread.__init__(self, name=name)
        self.name = name
        self.client_socket = client_socket

    def run(self):
        with self.client_socket:
            while True:
                recv_data = self.client_socket.recv(1024).decode().strip()
                if not recv_data:
                    break
                logging.info(f"{self.client_socket.getpeername()} send {recv_data}")

    @staticmethod
    def registration(firstname: str, lastname: str, password: str):
        data = json.dumps({"firstname": firstname,
                           "lastname": lastname,
                           "password": password})

        response = requests.get(os.getenv("API_URL_REGISTRATION"),
                                headers={"Content-type": "application/json", "Accept": "text/plain"},
                                data=data)
        json_data = json.loads(response.text)

        if not json_data["exist"]:
            response = requests.post(os.getenv("API_URL_REGISTRATION"),
                                     headers={"Content-type": "application/json", "Accept": "text/plain"},
                                     data=data)
            json_data = json.loads(response.text)
            return json_data["successful"]
        else:
            return not json_data["exist"]

    @staticmethod
    def authetication(firstname, lastname, password):
        data = json.dumps({"firstname": firstname,
                           "lastname": lastname,
                           "password": password})
        response = requests.get(os.getenv("API_URL_AUTHENTICATION"),
                                headers={"Content-type": "application/json", "Accept": "text/plain"},
                                data=data)
        json_data = json.loads(response.text)

        return json_data["successful"]
