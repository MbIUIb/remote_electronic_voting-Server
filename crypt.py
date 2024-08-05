import copy
import math
from random import choice

import rsa


def is_prime(num):
    prime = num > 1 and (num % 2 != 0 or num == 2) and (num % 3 != 0 or num == 3)
    i = 5
    d = 2

    while prime and i * i <= num:
        prime = num % i != 0
        i += d
        d = 6 - d  # чередование прироста 2 и 4: 5 + 2, 7 + 4, 11 + 2, и т.д.
    return prime


def gcd_and_simpl(n):
    result = [i for i in range(1, n + 1) if math.gcd(n, i) and is_prime(i) == 1]
    return choice(result)


def ascii_encrypt(message: str):
    int_msg = []
    for character in message:
        int_msg.append(ord(character))
    return int_msg


def mask(int_msg: list, masking_factor: int, e: int, n: int):
    int_msg_ = copy.deepcopy(int_msg)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index]*pow(masking_factor, e, n), 1, n)
    return int_msg_


def demask(int_msg: list, masking_factor: int, n: int):
    int_msg_ = copy.deepcopy(int_msg)
    m_ = pow(masking_factor, -1, n)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index] * m_, 1, n)
    return int_msg_


def sign(int_msg: list, d: int, n: int):
    int_msg_ = copy.deepcopy(int_msg)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index], d, n)
    return int_msg_


# Generate RSA keys
(izb_public_key, izb_private_key) = rsa.newkeys(16)
(ik_public_key, ik_private_key) = rsa.newkeys(16)

m = gcd_and_simpl(ik_public_key.n)

I = "Hello, World!"

ascii_msg = ascii_encrypt(I).copy()
mask_msg = mask(ascii_encrypt(I), m, ik_public_key.e, ik_public_key.n).copy()
signed_masked_msg = sign(mask_msg, ik_private_key.d, ik_private_key.n).copy()
demasked_msg = demask(signed_masked_msg, m, ik_public_key.n)
encode_msg = [pow(i, ik_public_key.e, ik_public_key.n) for i in demasked_msg]

print(f"msg in ascii: {ascii_msg}")
print(f"masked msg in ascii: {mask_msg}")
print(f"sign: {signed_masked_msg}")
print(f"demasked: {demasked_msg}")
print(f"msg: {encode_msg}")
