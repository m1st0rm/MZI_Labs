from typing import List

from bitarray import bitarray


s_box = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 15, 3, 7, 1, 0],
    [14, 7, 10, 12, 2, 8, 0, 13, 15, 6, 1, 9, 4, 5, 11, 3],
    [11, 10, 15, 5, 4, 8, 0, 3, 7, 12, 6, 2, 1, 13, 14, 9],
    [12, 6, 8, 2, 0, 11, 10, 7, 5, 9, 14, 3, 13, 15, 4, 1],
    [14, 9, 11, 5, 7, 0, 6, 3, 2, 12, 1, 10, 4, 13, 8, 15],
    [15, 9, 4, 8, 1, 7, 2, 12, 6, 0, 10, 14, 5, 3, 11, 13],
    [8, 15, 3, 1, 10, 13, 12, 5, 7, 0, 9, 4, 6, 11, 2, 14],
    [4, 10, 7, 12, 0, 8, 15, 9, 2, 13, 6, 1, 11, 14, 5, 3],
]


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
    bits_block_1: bitarray, bits_block_2: bitarray, key_bits: List[bitarray]
) -> List[bitarray]:
    for i in range(0, 32):
        int1 = int(bits_block_1.to01(), 2)
        int2 = int(key_bits[i].to01(), 2)
        result_int = (int1 + int2) % (2**32)
        mod_result_bits = bitarray(format(result_int, "032b"))

        segments = [mod_result_bits[i : i + 4] for i in range(0, len(mod_result_bits), 4)]

        for j in range(0, len(segments)):
            segments[j] = bitarray(format(s_box[j][int(segments[j].to01(), 2)], "04b"))

        combined_bits = bitarray()
        for segment in segments:
            combined_bits.extend(segment)

        left_cycled_bits = combined_bits[11:] + combined_bits[:11]
        xor_bits = left_cycled_bits ^ bits_block_2
        bits_block_2 = bits_block_1
        bits_block_1 = xor_bits

    return bits_block_1 + bits_block_2
