from typing import List

from bitarray import bitarray


def key_to_bits(content: str) -> List[bitarray]:
    byte_array = content.encode("utf-8")
    bits_array = bitarray()
    bits_array.frombytes(byte_array)
    bit_segments = [bits_array[i : i + 32] for i in range(0, len(bits_array), 32)]

    return bit_segments
