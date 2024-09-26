import ast
import base64
import json
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
    def __init__(self, client_socket: socket.SocketType,
                 server_public_key: rsa.PublicKey,
                 server_private_key: rsa.PrivateKey):
        Thread.__init__(self)
        self.client_socket = client_socket
        self.server_public_key = server_public_key
        self.server_private_key = server_private_key

        self.server_pubkey_n = server_public_key.n
        self.server_pubkey_e = server_public_key.e
        self.client_pubkey_e = None
        self.client_pubkey_n = None

        self.running = True

        self.authorized = False

    def run(self):
        """Запуск работы нового потока обработчика клиентов.
            Переопределныый метод :py:func:`run()` класса :py:class:`threading.Thread`

        :return: ``None``
       """

        with self.client_socket:
            while self.running:
                recv_data = self.client_socket.recv(16384).decode()
                if not recv_data:
                    self.running = False
                    break

                # {"request": "something", "item1": "val1", ...}
                json_data = json.loads(recv_data)

                self.requet_matcher(json_data)

    def requet_matcher(self, json_data: dict[str: str]):
        """Производит обработку запросов.

        :param dict json_data: словарь, принятый от пользователя и содержащий
            данные для обработки.
        :return: ``None``
        """

        match json_data[jk.REQUEST]:
            case jk.KEY_EXCHANGE:
                # {"request": "key_exchange",
                # "client_pubkey_n": "key_n...",
                # "client_pubkey_e": "key_e..."}
                self.rsa_key_exchange(json_data)

            case jk.REGISTRATION:
                # {"request": "registration",
                # "firstname": "mbiuib",
                # "lastname": "mbiuiblastname",
                # "password": "rsa_passwd_in_base64"}
                self.registration_handler(json_data)

            case jk.AUTENTICATION:
                # {"request": "authentication",
                # "firstname": "mbiuib",
                # "lastname": "mbiuiblastname",
                # "password": "rsa_passwd_in_base64"}
                self.authorized = self.autentication_handler(json_data)
                print(self.authorized)

            case jk.CRYPT_STAGE_1_INIT:
                # {"request": "CRYPT_STAGE_1_INIT",
                # "firstname": "mbiuib",
                # "lastname": "mbiuiblastname"}
                self.crypt_stge_1_init_handler(json_data)

            case _:
                print(json_data)

    def rsa_key_exchange(self, json_data: dict[str: str]):
        """Производит обмен RSA ключами. Первым отправляет ключи клиент, затем сервер.

        :return: ``None``
        """

        self.client_pubkey_n = int(json_data[jk.KEYEX_CLIENT_PUB_N])
        self.client_pubkey_e = int(json_data[jk.KEYEX_CLIENT_PUB_E])

        send_data = {jk.KEYEX_SERVER_PUB_N: str(self.server_pubkey_n),
                     jk.KEYEX_SERVER_PUB_E: str(self.server_pubkey_e)}
        self.send_json(send_data)

    def registration_handler(self, json_data: dict[str: str]) -> bool:
        """Производит обработку запроса регистрации.

        Для осуществления данного запроса, клиенту необходимо отправить JSON,
        содержащий следующие данные:
        *{
        "request": "registration",
        "firstname": "clients name",
        "lastname": "clients lastname",
        "password": "clients password"
        }*

        Отправляет ответ вида:
        *{"reg_state": "Successful"}*,
        *{"reg_state": "Voter exists"}*,
        *{"reg_state": "Registration failed"}*


        :param dict json_data: словарь, содержащий принятые данные клиента.
        :return: ``True`` или ``False``
        """

        json_data = self.decrypt_dict(json_data)
        reg_state = self.db_registration_request(json_data[jk.FIRSTNAME],
                                                 json_data[jk.LASTNAME],
                                                 json_data[jk.PASSWORD])
        send_data = self.encrypt_dict({jk.REG_STATE: reg_state})
        _json_data = json.dumps(send_data).encode()
        self.client_socket.send(_json_data)

        return True if reg_state == "Successful" else False

    def autentication_handler(self, json_data: dict[str: str]) -> bool:
        """Производит обработку запроса аутентификации.

        Для осуществления данного запроса, клиенту необходимо отправить JSON,
        содержащий следующие данные:
        *{
        "request": "authentication",
        "firstname": "clients name",
        "lastname": "clients lastname",
        "password": "clients password"
        }*

        Отправляет ответ вида:
        *{"auth_state": "True"}*,
        *{"auth_state": "False"}*

        После обработки изменится *self.authorized* на ``True`` или ``False``

        :param dict json_data: словарь, содержащий принятые данные клиента.
        :return: ``True`` или ``False``
        """

        json_data = self.decrypt_dict(json_data)
        auth_state = self.db_authetication_request(json_data[jk.FIRSTNAME],
                                                   json_data[jk.LASTNAME],
                                                   json_data[jk.PASSWORD])
        send_data = self.encrypt_dict({jk.AUTH_STATE: auth_state})
        _json_data = json.dumps(send_data).encode()
        self.client_socket.send(_json_data)

        return ast.literal_eval(auth_state)

    def crypt_stge_1_init_handler(self, json_data: dict[str: str]) -> None:
        """Производит обработку запроса даннотых для инициализации криптографического
        протокола.

        Для осуществления данного запроса, клиенту необходимо отправить JSON,
        содержащий следующие данные:
        *{
        "request": "CRYPT_STAGE_1_INIT",
        "firstname": "mbiuib",
        "lastname": "mbiuiblastname"
        }*

        Отправляет ответ вида:
        *{"id": 6, "iden_num_len": 10}*

        :param dict json_data: словарь, содержащий принятые данные клиента.
        :return: ``None``
        """

        send_data = self.encrypt_dict(self.db_crypt_stage_1_request(json_data[jk.FIRSTNAME],
                                                                    json_data[jk.LASTNAME]))
        _json_data = json.dumps(send_data).encode()
        self.client_socket.send(_json_data)

    def send_json(self, message_dict: dict[str: str]):
        json_data = json.dumps(message_dict)
        self.client_socket.send(json_data.encode())

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
            if key == jk.PASSWORD:
                encrypt_dict[key] = self.encrypt_str(json_data[key])
            else:
                encrypt_dict[key] = json_data[key]
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
            if key == jk.PASSWORD:
                json_data[key] = self.decrypt_str(encrypt_json[key])
            else:
                json_data[key] = encrypt_json[key]

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

    @staticmethod
    def db_crypt_stage_1_request(firstname: str, lastname: str) -> dict[str: str]:
        """Выполняет запрос к базе данных, для возврата id избирателя и длину
        для генерации идентификационного номмера.

        :param str firstname: имя пользователя.
        :param str lastname: фамилия пользователя.
        :return: словарь, содержащий id пользователя и длину для генерации
                 идентификационного номмера
        :rtype: dict[str: str]

        :example:
        >>> ClientHandler.db_crypt_stage_1_request("mbiuib","mbiuib")
        {'id': 6, 'iden_num_len': 10}
        """

        data = json.dumps({jk.FIRSTNAME: firstname,
                           jk.LASTNAME: lastname})
        response = requests.get(os.getenv("API_URL_VOTER_INFO"),
                                headers=jk.JSON_HEADERS,
                                data=data)
        json_data = json.loads(response.text)

        return json_data
