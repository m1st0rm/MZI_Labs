import logging
from typing import List


logging.basicConfig(
    filename="encryption.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

S_BOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
]

KEY_256 = [
    0x12345678,
    0x23456789,
    0x34567890,
    0x45678901,
    0x56789012,
    0x67890123,
    0x78901234,
    0x89012345,
]


def apply_substitution(x: int) -> int:
    logging.debug(f"Applying substitution to: {x:08X}")
    result = 0
    for i in range(8):
        nibble = (x >> (4 * i)) & 0xF
        result |= S_BOX[i][nibble] << (4 * i)
    logging.debug(f"Substitution result: {result:08X}")
    return result


def cyclic_shift_left(x: int, shift_by: int) -> int:
    logging.debug(f"Applying cyclic shift left to: {x:08X} by {shift_by} bits")
    result = ((x << shift_by) & 0xFFFFFFFF) | (x >> (32 - shift_by))
    logging.debug(f"Result after shift: {result:08X}")
    return result


def gost_round(key: int, data: int) -> int:
    logging.debug(f"Performing GOST round with key: {key:08X} and data: {data:08X}")
    result = cyclic_shift_left(apply_substitution((data + key) & 0xFFFFFFFF), 11)
    logging.debug(f"Result after GOST round: {result:08X}")
    return result


def encrypt_block(block: int, key: List[int]) -> int:
    logging.info(f"Encrypting block: {block:016X}")
    n1 = block >> 32
    n2 = block & 0xFFFFFFFF
    for i in range(24):
        n1, n2 = n2, n1 ^ gost_round(key[i % 8], n2)

    for i in range(8):
        n1, n2 = n2, n1 ^ gost_round(key[7 - i], n2)

    encrypted_block = (n2 << 32) | n1
    logging.info(f"Encrypted block: {encrypted_block:016X}")
    return encrypted_block


def decrypt_block(block: int, key: List[int]) -> int:
    logging.info(f"Decrypting block: {block:016X}")
    n1 = block >> 32
    n2 = block & 0xFFFFFFFF

    for i in range(8):
        n1, n2 = n2, n1 ^ gost_round(key[i], n2)

    for i in range(24):
        n1, n2 = n2, n1 ^ gost_round(key[7 - i % 8], n2)

    decrypted_block = (n2 << 32) | n1
    logging.info(f"Decrypted block: {decrypted_block:016X}")
    return decrypted_block


def transform_file(
    input_file: str, output_file: str, key: List[int], process_block_function
) -> None:
    logging.info(f"Processing file: {input_file} -> {output_file}")
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        while chunk := f_in.read(8):
            if len(chunk) < 8:
                chunk += b" " * (8 - len(chunk))
            block = int.from_bytes(chunk, byteorder="little")
            transformed_block = process_block_function(block, key)
            f_out.write(transformed_block.to_bytes(8, byteorder="little"))


def encrypt_file(input_file: str, output_file: str, key: List[int]) -> None:
    transform_file(input_file, output_file, key, encrypt_block)


def decrypt_file(input_file: str, output_file: str, key: List[int]) -> None:
    transform_file(input_file, output_file, key, decrypt_block)


encrypt_file("input.txt", "encrypted.txt", KEY_256)
decrypt_file("encrypted.txt", "decrypted.txt", KEY_256)
