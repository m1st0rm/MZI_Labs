from typing import List

from bitarray import bitarray


def text_to_bits(content: str) -> List[bitarray]:
    byte_array = content.encode("utf-8")
    bits_array = bitarray()
    bits_array.frombytes(byte_array)
    bit_segments = [bits_array[i : i + 64] for i in range(0, len(bits_array), 64)]

    return bit_segments


def bits_to_text(bits_array: List[bitarray]) -> str:
    text = ""
    for bit_array in bits_array:
        text_part = bit_array.tobytes().decode("utf-8")
        text += text_part

    return text
