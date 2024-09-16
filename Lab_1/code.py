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

key = [
    0x12345678,
    0x23456789,
    0x34567890,
    0x45678901,
    0x56789012,
    0x67890123,
    0x78901234,
    0x89012345,
]


def encrypt_block(block, key):
    n1 = block >> 32
    n2 = block & 0xFFFFFFFF

    for i in range(24):
        n1, n2 = n2, n1 ^ gost_round(key[i % 8], n2)

    for i in range(8):
        # обратный цикл
        n1, n2 = n2, n1 ^ gost_round(key[7 - i], n2)

    return (n2 << 32) | n1


def gost_round(key, data):
    # складывает данные и ключ по модулю 2^32
    return left_rotate(substitute((data + key) & 0xFFFFFFFF), 11)


# новое 32 битное значение
def substitute(x):
    result = 0
    # извлечения отдельных 4-битных частей из 32-битного числа x
    for i in range(8):  # побит. И 00001111
        result |= (S_BOX[i][(x >> (4 * i)) & 0xF]) << (4 * i)
    return result


def left_rotate(x, bits):
    # оставляем младшие 32 бита
    return ((x << bits) & 0xFFFFFFFF) | (x >> (32 - bits))


def decrypt_block(block, key):
    n1 = block >> 32
    n2 = block & 0xFFFFFFFF

    for i in range(8):
        n1, n2 = n2, n1 ^ gost_round(key[i], n2)

    for i in range(24):
        n1, n2 = n2, n1 ^ gost_round(key[7 - i % 8], n2)

    return (n2 << 32) | n1


def encrypt_file(input_file, output_file, key):
    # в бинарном режиме
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        while chunk := f_in.read(8):
            if len(chunk) < 8:
                chunk += b"\0" * (8 - len(chunk))  # дополняем нулями до 64 бит
            # конвертируем байтовую строку в целое число(младший байт впереди)
            block = int.from_bytes(chunk, byteorder="little")
            encrypted_block = encrypt_block(block, key)
            f_out.write(encrypted_block.to_bytes(8, byteorder="little"))


def decrypt_file(input_file, output_file, key):
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        while chunk := f_in.read(8):
            block = int.from_bytes(chunk, byteorder="little")
            decrypted_block = decrypt_block(block, key)
            f_out.write(decrypted_block.to_bytes(8, byteorder="little").rstrip(b"\0"))


encrypt_file("input.txt", "encrypted.txt", key)
decrypt_file("encrypted.txt", "decrypted.txt", key)
