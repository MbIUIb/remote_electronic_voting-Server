import base64
import json
import logging
import os
import socket
from threading import Thread

import requests
import rsa
from dotenv import load_dotenv

from json_keys import JsonKeys as jk

# env
load_dotenv()


class ClientHandler(Thread):
    def __init__(self, name,
                 client_socket: socket.SocketType,
                 server_public_key: rsa.PublicKey,
                 server_private_key: rsa.PrivateKey):

        Thread.__init__(self, name=name)
        self.name = name
        self.client_socket = client_socket
        self.server_public_key = server_public_key
        self.server_private_key = server_private_key
        self.client_pubkey_n = None
        self.client_pubkey_e = None
        self.server_pubkey_n = self.server_public_key.n
        self.server_pubkey_e = self.server_public_key.e
        self.server_pubkey_d = self.server_private_key.d

    def run(self):
        with self.client_socket:
            self.rsa_key_exchange()

            while True:
                print("start")
                recv_data = self.client_socket.recv(16384).decode()
                if not recv_data:
                    break
                logging.info(f"{self.client_socket.getpeername()} send {recv_data}")

                json_data = self.json_decrypt(json.loads(recv_data))

                match json_data[jk.REQUEST]:
                    case jk.REGISTRATION:
                        reg_state = self.registration(json_data[jk.FIRSTNAME],
                                                      json_data[jk.LASTNAME],
                                                      json_data[jk.PASSWORD])
                        send_data = self.json_encrypt({jk.REG_STATE: reg_state})
                        json_data = json.dumps(send_data).encode()
                        self.client_socket.send(json_data)

                    case jk.AUTENTICATION:
                        auth_state = self.authetication(json_data[jk.FIRSTNAME],
                                                        json_data[jk.LASTNAME],
                                                        json_data[jk.PASSWORD])
                        send_data = self.json_encrypt({jk.AUTH_STATE: str(auth_state)})
                        json_data = json.dumps(send_data).encode()
                        self.client_socket.send(json_data)

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

    def rsa_key_exchange(self):
        self.client_pubkey_n = int(self.client_socket.recv(4096).decode())
        self.client_pubkey_e = int(self.client_socket.recv(4096).decode())

        self.client_socket.send(str(self.server_pubkey_n).encode())
        self.client_socket.send(str(self.server_pubkey_e).encode())

    def json_encrypt(self, json_data: dict[str: str]) -> dict[str: str]:
        encrypt_dict = {}
        for item in json_data:
            encrypt = rsa.encrypt(json_data[item].encode(),
                                  rsa.PublicKey(self.client_pubkey_n,
                                                self.client_pubkey_e))
            encrypt_dict[item] = base64.b64encode(encrypt).decode()
        return encrypt_dict

    def json_decrypt(self, encrypt_json: dict[str: str]) -> dict[str: str]:
        json_data = {}
        for item in encrypt_json:
            decode = base64.b64decode(encrypt_json[item])
            json_data[item] = rsa.decrypt(decode, self.server_private_key).decode()
        return json_data

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
