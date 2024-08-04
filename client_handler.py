import json
import logging
import os
import socket
from threading import Thread

import requests
from dotenv import load_dotenv

from json_keys import JsonKeys as jk

# env
load_dotenv()


class ClientHandler(Thread):
    def __init__(self, name, client_socket: socket.SocketType):
        Thread.__init__(self, name=name)
        self.name = name
        self.client_socket = client_socket

    def run(self):
        with self.client_socket:
            while True:
                recv_data = self.client_socket.recv(1024).decode()
                if not recv_data:
                    break
                logging.info(f"{self.client_socket.getpeername()} send {recv_data}")

                json_data = json.loads(recv_data)

                match json_data[jk.REQUEST]:
                    case jk.REGISTRATION:
                        reg_state = self.registration(json_data[jk.FIRSTNAME],
                                                      json_data[jk.LASTNAME],
                                                      json_data[jk.PASSWORD])
                        send_data = {jk.REG_STATE: reg_state}
                        self.client_socket.send(json.dumps(send_data).encode())

                    case jk.AUTENTICATION:
                        auth_state = self.authetication(json_data[jk.FIRSTNAME],
                                                        json_data[jk.LASTNAME],
                                                        json_data[jk.PASSWORD])
                        send_data = {jk.AUTH_STATE: auth_state}

                        self.client_socket.send(json.dumps(send_data).encode())

                        if auth_state:
                            stage_1 = self.client_socket.recv(1024).decode()
                            print(stage_1)
                            # stage 1 of cryptography protocol
                            # ...
                            # ...

                        else:
                            break

                    case _:
                        break

    @staticmethod
    def registration(firstname: str, lastname: str, password: str) -> str:
        data = json.dumps({jk.FIRSTNAME: firstname,
                           jk.LASTNAME: lastname,
                           jk.PASSWORD: password})
        response = requests.get(os.getenv("API_URL_REGISTRATION"),
                                headers=jk.JSON_HEADERS,
                                data=data)
        json_data = json.loads(response.text)

        if json_data[jk.EXISTS]:
            return "Voter exists"
        else:
            response = requests.post(os.getenv("API_URL_REGISTRATION"),
                                     headers=jk.JSON_HEADERS,
                                     data=data)
            json_data = json.loads(response.text)
            return "Successful" if json_data[jk.SUCCESSFUL] else "Registration failed"

    @staticmethod
    def authetication(firstname: str, lastname: str, password: str) -> bool:
        data = json.dumps({jk.FIRSTNAME: firstname,
                           jk.LASTNAME: lastname,
                           jk.PASSWORD: password})
        response = requests.get(os.getenv("API_URL_AUTHENTICATION"),
                                headers=jk.JSON_HEADERS,
                                data=data)
        json_data = json.loads(response.text)

        return json_data[jk.SUCCESSFUL]
