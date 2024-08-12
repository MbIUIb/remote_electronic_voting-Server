import copy
import math
from random import choice

import rsa


def is_prime(num: int) -> bool:
    """Проверка числа на простоту.

    :param int num: проверяемое число.
    :return: ``True`` или ``False``.
    :rtype: bool

    :example:
    >>> is_prime(65537)
    True
    >>> is_prime(65538)
    False
    """

    prime = num > 1 and (num % 2 != 0 or num == 2) and (num % 3 != 0 or num == 3)
    i = 5
    d = 2

    while prime and i * i <= num:
        prime = num % i != 0
        i += d
        d = 6 - d  # чередование прироста 2 и 4: 5 + 2, 7 + 4, 11 + 2, и т.д.
    return prime


def gcd_and_simpl(n: int) -> int:
    """Возвращает случайное простое число, взаимнопростое с аргументом.

    :param int n: число для проверки.
    :return: случайное простое число взаимнопростое с проверяемым.
    :rtype: int

    :example:
    >>> gcd_and_simpl(65537)
    16187
    >>> gcd_and_simpl(65537)
    5693
    """

    result = [i for i in range(1, n + 1) if math.gcd(n, i) and is_prime(i) == 1]
    return choice(result)


def ascii_encode(message: str) -> list[int]:
    """Преобразует сообщение в список ASCII кодов.

    :param str message: сообение для преобразования в список ASCII кодов.
    :return: список ASCII кодов.
    :rtype: list[int]

    :example:
    >>> ascii_encode("Hello world!")
    [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33]
    """

    int_msg = []
    for character in message:
        int_msg.append(ord(character))
    return int_msg


def ascii_decode(int_msg: list[int]) -> str:
    """Преобразует список ASCII кодов в сообщение.

    :param int_msg: сообение для преобразования в список ASCII кодов.
    :return: список ASCII кодов.
    :rtype: str

    :example:
    >>> ascii_decode([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33])
    'Hello world!'
    """

    message = ""
    for encode_character in int_msg:
        message += chr(encode_character)
    return message


def mask(int_msg: list[int], masking_factor: int, e: int, n: int) -> list[int]:
    """Маскирование сообщения, представленного списком кодов.

    :param list[int] int_msg: сообщение для маскирования, представленное списком кодов.
    :param int masking_factor: число, взаимнопростое с параметром n,
        обычно известно только стороне, производящей маскирование.
    :param int e: открытая экспонента, первая часть открытого ключа RSA.
    :param int n: простое число, вторая часть открытого ключа RSA.
    :return: список маскированных кодов.
    :rtype: list[int]

    :example:
    >>> mask([72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33], 22277, 65537, 37327)
    [5743, 5464, 27278, 27278, 25962, 30468, 35732, 34895, 25962, 24646, 27278, 18345, 22851]
    """

    int_msg_ = copy.deepcopy(int_msg)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index]*pow(masking_factor, e, n), 1, n)
    return int_msg_


def demask(int_msg: list[int], masking_factor: int, n: int) -> list[int]:
    """Демаскирование сообщения, представленного списком кодов

    :param list[int] int_msg: Сообщение для демаскирования, представленное списком чисел.
    :param int masking_factor: Число, взаимнопростое с параметром n,
        обычно известно только стороне, производящей маскирование.
    :param int n: Простое число, часть открытого ключа RSA.
    :return: список демаскированных кодов.
    :rtype: list[int]

    :example:
    >>> demask([12684, 36978, 6287, 6287, 20884, 27693, 22565, 21044, 20884, 14602, 6287, 35648, 1227], 22277, 37327)
    [20937, 21610, 31575, 31575, 2831, 6469, 36073, 22871, 2831, 18541, 31575, 22999, 32369]
    """

    int_msg_ = copy.deepcopy(int_msg)
    m_ = pow(masking_factor, -1, n)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index] * m_, 1, n)
    return int_msg_


def sign(int_msg: list, d: int, n: int) -> list[int]:
    """Криптографическая подпись сообщения, предствленного списком кодов.

    :param list[int] int_msg: сообщение для подписи, представленное списком кодов.
    :param int d: закрытая экспонента, часть закрытого ключа RSA.
    :param int n: простое число, вторая часть открытого ключа RSA.
    :return: список подписанных кодов.
    :rtype: list[int]

    :example:
    >>> sign([5743, 5464, 27278, 27278, 25962, 30468, 35732, 34895, 25962, 24646, 27278, 18345, 22851], 9953, 37327)
    [12684, 36978, 6287, 6287, 20884, 27693, 22565, 21044, 20884, 14602, 6287, 35648, 1227]
    """

    int_msg_ = copy.deepcopy(int_msg)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index], d, n)
    return int_msg_


def sign_check(int_msg: list[int], e: int, n: int) -> list[int]:
    """Снимает криптографическую подпись.

    :param list[int] int_msg: сообщение для снятия подписи, представленное списком кодов.
    :param int e: открытая экспонента, первая часть открытого ключа RSA.
    :param int n: простое число, вторая часть открытого ключа RSA.
    :return: список кодов без подписи.
    :rtype: list[int]

    :example:
    >>> sign_check([20937, 21610, 31575, 31575, 2831, 6469, 36073, 22871, 2831, 18541, 31575, 22999, 32369], 65537, 37327)
    [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
    """
    return [pow(i, e, n) for i in int_msg]


if __name__ == '__main__':
    # Generate RSA keys
    izb_public_key, izb_private_key = rsa.newkeys(16)
    ik_public_key, ik_private_key = rsa.newkeys(16)

    m = gcd_and_simpl(ik_public_key.n)
    I = "Hello, world!"

    ascii_msg = ascii_encode(I).copy()
    mask_msg = mask(ascii_encode(I), m, ik_public_key.e, ik_public_key.n).copy()
    signed_masked_msg = sign(mask_msg, ik_private_key.d, ik_private_key.n).copy()
    demasked_msg = demask(signed_masked_msg, m, ik_public_key.n)
    encode_msg = sign_check(demasked_msg, ik_public_key.e, ik_public_key.n)
    msg = ascii_decode(encode_msg)

    print(f"msg in ascii: {ascii_msg}")
    print(f"masked msg in ascii: {mask_msg}")
    print(f"sign: {signed_masked_msg}")
    print(f"demasked: {demasked_msg}")
    print(f"msg: {encode_msg}")
    print(msg)
