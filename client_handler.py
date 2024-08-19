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
    """
    Обработчик клиетов для системы дистанционного эоектронного
    голосования на основе слепой подписи.
    """

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
        self.running = True

    def run(self) -> None:
        """Запуск работы нового потока обработчика клиентов.
            Переопределныый метод :py:func:`run()` класса :py:class:`threading.Thread`

        :return: ``None``
        """

        with self.client_socket:
            self.rsa_key_exchange()

            self.client_handler_cycle()

    def client_handler_cycle(self) -> None:
        """Цикл для принятия и делегирования обработки запросов пользователей.

        :return: ``None``
        """

        while self.running:
            _recv_data = self.client_socket.recv(16384).decode()
            if not _recv_data or _recv_data == '':
                self.running = False
                break
            logging.info(f"{self.client_socket.getpeername()} send {_recv_data}")

            _json_data = self.decrypt_dict(json.loads(_recv_data))

            self.request_matcher(_json_data)

    def request_matcher(self, json_data) -> None:
        """Производит обработку запросов.

        :param dict json_data: словарь, принятый от пользователя и содержащий
            данные для обработки.
        :return: ``None``
        """

        match json_data[jk.REQUEST]:
            case jk.REGISTRATION:
                reg_state = self.db_registration_request(json_data[jk.FIRSTNAME],
                                                         json_data[jk.LASTNAME],
                                                         json_data[jk.PASSWORD])
                send_data = self.encrypt_dict({jk.REG_STATE: reg_state})
                _json_data = json.dumps(send_data).encode()
                self.client_socket.send(_json_data)

            case jk.AUTENTICATION:
                auth_state = self.db_authetication_request(json_data[jk.FIRSTNAME],
                                                           json_data[jk.LASTNAME],
                                                           json_data[jk.PASSWORD])
                send_data = self.encrypt_dict({jk.AUTH_STATE: auth_state})
                _json_data = json.dumps(send_data).encode()
                self.client_socket.send(_json_data)

                if auth_state:
                    stage_1 = self.client_socket.recv(1024).decode()
                    print(stage_1)
                    # stage 1 of cryptography protocol
                    # ...
                    # ...

                else:
                    self.running = False

            case _:
                self.running = False

    def rsa_key_exchange(self) -> None:
        """Производит обмен RSA ключами. Первым отправляет ключи клиент, затем сервер.

        :return: ``None``
        """

        self.client_pubkey_n = int(self.client_socket.recv(4096).decode())
        self.client_pubkey_e = int(self.client_socket.recv(4096).decode())

        self.client_socket.send(str(self.server_pubkey_n).encode())
        self.client_socket.send(str(self.server_pubkey_e).encode())

    def encrypt_str(self, string_to_encrypt: str) -> str:
        """Зашифровывает строку алгоритмом RSA и возвращает строку, закодированную в Base64.

        :param str string_to_encrypt: строка для шифрования.
        :return: зашифрованная строка.
        :rtype: str

        :example:
        >>> ClientHandler.encrypt_str("string")
        "bTuT0pIxF3hbawCJpZqLdELL3ekeuhHRSf9qiLkFVvUvE86bHEUG9WgvJ2UYQ+oMZaetv6EL6Ae/T7E1+XYmjQ=="
        """

        encrypt_str = rsa.encrypt(string_to_encrypt.encode(),
                                  rsa.PublicKey(self.client_pubkey_n,
                                                self.client_pubkey_e))
        return base64.b64encode(encrypt_str).decode()

    def decrypt_str(self, string_to_decrypt: str) -> str:
        """Принимает строку, кодированную Base64 и расшифровывает алгоитмом RSA.

        :param str string_to_decrypt: строка для расшифровывания.
        :return: расшифрованная строка.
        :rtype: str

        :example:
        >>>ClientHandler.decrypt_str("bTuT0pIxF3hbawCJpZqLdELL3ekeuhHRSf9qiLkFVvUvE86bHEUG9WgvJ2UYQ+oMZaetv6EL6Ae/T7E1+XYmjQ==")
        "string"
        """
        decode_str = base64.b64decode(string_to_decrypt)
        return rsa.decrypt(decode_str, self.server_private_key).decode()

    def encrypt_dict(self, json_data: dict[str: str]) -> dict[str: str]:
        """Зашифровывает значения переданного словаря.

        :param json_data: словарь, содержащий данные JSON в формате *{"строка": "строка"}*
        :return: словарь с зашифрованными значениями и кодированными в Base64:
            *{"строка": "зашифрованная_строка"}*
        :rtype: dict

        :example:
        >>> ClientHandler.encrypt_dict({"key1": "val1", "key2": "val2"})
        {'key1': 'NVirdz6JkaTlGxviWvzK0JcAzCoCV4W+1pxHxO0mHvjXWBpY5K2ZevH7F9dAzvgEm9jcdDLqFF1kZHpiL0GXAA==',
         'key2': 'D4iUG3lVXVLd4T4VdppzOdqegnRyIhDWjobPlIXGSIWEUhQfNnXW7rOy2G7zhfnG5mjQMVEgug5haIUugEkOQw=='}
        """

        encrypt_dict = {}
        for key in json_data:
            encrypt_dict[key] = self.encrypt_str(json_data[key])
        return encrypt_dict

    def decrypt_dict(self, encrypt_json: dict[str: str]) -> dict[str: str]:
        """Расшифровывает значения переданного словаря.

        :param dict encrypt_json: словарь, содержащий данные JSON в формате
            *{"строка": "зашифрованная_строка"}*
        :return: словарь с расшифрованными значениями: *{"строка": "расшифрованная_строка"}*
        :rtype: dict

        :example:
        >>> ClientHandler.decrypt_dict({'key1': 'NVirdz6JkaTlGxviWvzK0JcAzCoCV4W+1pxHxO0mHvjXWBpY5K2ZevH7F9dAzvgEm9jcdDLqFF1kZHpiL0GXAA==', 'key2': 'D4iUG3lVXVLd4T4VdppzOdqegnRyIhDWjobPlIXGSIWEUhQfNnXW7rOy2G7zhfnG5mjQMVEgug5haIUugEkOQw=='},)
        {'key1': 'val1', 'key2': 'val2'}
        """

        json_data = {}
        for key in encrypt_json:
            json_data[key] = self.decrypt_str(encrypt_json[key])
        return json_data

    @staticmethod
    def db_registration_request(firstname: str, lastname: str, password: str) -> str:
        """Выполняет запрос к базе данных, для проверки регистрации пользователя.

         Если пользователя не существует, регистрирует его и возвращает строку ``Successful``.
         Если пользователь уже зарегистрирован, возвращает строку ``Voter exists``.
         В случае ошибки на стороне БД, возвращает строку ``Registration failed``.

        :param str firstname: имя пользователя.
        :param str lastname: фамилия пользователя.
        :param str password: пароль пользователя.
        :return: строка-статус: ``Successful``, ``Voter exists`` или ``Registration failed``
        :rtype: str

        :example:
        >>> ClientHandler.db_registration_request("mbiuib","mbiuib1","mbiuib123")
        "Voter exists"
        >>> ClientHandler.db_registration_request("mbiuib999","mbiuib1123","mbiuib123123")
        "Successful"
        """

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
    def db_authetication_request(firstname: str, lastname: str, password: str) -> str:
        """Выполняет запрос к базе данных, для аутентификации пользователя.

        В случает успешной аутентификации возвращается ``"True"``, иначе ``"False"``.

        :param str firstname: имя пользователя.
        :param str lastname: фамилия пользователя.
        :param str password: пароль пользователя.
        :return: строка-статус: ``True`` или ``False``
        :rtype: str

        :example:
        >>> ClientHandler.db_authetication_request("mbiuib","mbiuib1","mbiuib123")
        "True"
        >>> ClientHandler.db_authetication_request("mbiuib","mbiuib1","bad_pass")
        "False"
        """

        data = json.dumps({jk.FIRSTNAME: firstname,
                           jk.LASTNAME: lastname,
                           jk.PASSWORD: password})
        response = requests.get(os.getenv("API_URL_AUTHENTICATION"),
                                headers=jk.JSON_HEADERS,
                                data=data)
        json_data = json.loads(response.text)

        return str(json_data[jk.SUCCESSFUL])
