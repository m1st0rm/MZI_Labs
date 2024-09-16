from typing import List

from bitarray import bitarray


def key_looper_encrypt(key_bits: List[bitarray]) -> List[bitarray]:
    keys_looped = []

    for i in range(0, 24):
        keys_looped.append(key_bits[i % 8])

    for i in range(24, 32):
        keys_looped.append(key_bits[31 - i])

    return keys_looped


def key_looper_decrypt(key_bits: List[bitarray]) -> List[bitarray]:
    keys_looped = []

    for i in range(0, 8):
        keys_looped.append(key_bits[i])

    for i in range(8, 32):
        keys_looped.append(key_bits[(31 - i) % 8])

    return keys_looped
