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


def encrypt_bits(
    text_bits: List[bitarray], key_unlooped_bits: List[bitarray]
) -> List[bitarray]:
    encrypted_bits = []
    key_looped_bits = key_looper_encrypt(key_unlooped_bits)

    for i in range(0, len(text_bits)):
        encrypted_bits.append(
            encryption_function(text_bits[i][:32], text_bits[i][32:], key_looped_bits)
        )

    return encrypted_bits


def encryption_function(
    bits_block_1: bitarray, bits_block_2: bitarray, key: List[bitarray]
) -> List[bitarray]:
    for i in range(0, 32):
        pass
