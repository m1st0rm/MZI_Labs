import math

import numpy as np


class HammingKeyGenerator:
    def __init__(self, kgen: int):
        self.kgen = kgen
        self.k = 2**self.kgen - self.kgen - 1
        self.n = 2**self.kgen - 1
        self.generator_matrix = self.generate_hamming_matrix()
        self.invertible_matrix = self.generate_invertible_matrix()
        self.permutation_matrix = self.generate_permutation_matrix()
        self.public_key = (
            np.matmul(
                np.matmul(self.invertible_matrix, self.generator_matrix),
                self.permutation_matrix,
            )
            % 2
        )

    def generate_hamming_matrix(self) -> np.ndarray:
        identity_gen = np.identity(self.kgen)
        identity_k = np.identity(self.k)
        left_matrix = np.zeros((self.kgen, 2**self.kgen - 1 - self.kgen)).T
        row_count = 0
        for i in range(2**self.kgen):
            if i + 1 != 1:
                if (i + 1) & i != 0:
                    binary_str = np.binary_repr(i + 1)
                    column = np.zeros((len(binary_str), 1))
                    for j in range(len(binary_str)):
                        column[-j - 1] = binary_str[j]
                    column = np.pad(column, (0, self.kgen - len(binary_str)), "constant")
                    left_matrix[row_count] = column.T[0]
                    row_count += 1
        left_matrix = left_matrix.T
        self.parity_check_matrix = np.block([left_matrix, identity_gen])
        self.generator_matrix = np.block([identity_k, np.transpose(left_matrix)])
        return self.generator_matrix

    def generate_invertible_matrix(self) -> np.ndarray:
        matrix = np.random.randint(0, 2, (self.k, self.k), dtype=np.uint)
        while np.linalg.det(matrix) == 0:
            matrix = np.random.randint(0, 2, (self.k, self.k), dtype=np.uint)
        return matrix

    def generate_permutation_matrix(self) -> np.ndarray:
        matrix = np.identity(self.n, dtype=np.uint)
        return matrix[np.random.permutation(self.n)]


class Encoder:
    def __init__(self, message: np.ndarray, public_key: np.ndarray, error_count: int = 1):
        self.public_key = public_key
        self.message = message
        self.k, self.n = public_key.shape
        self.error_count = error_count
        self.error_vector = self.generate_errors()
        self.encoded_message = self.encode()

    def generate_errors(self) -> np.ndarray:
        errors = np.zeros(self.n)
        idx_list = np.random.choice(self.n, self.error_count, replace=False)
        for idx in idx_list:
            errors[idx] = 1
        return errors

    def encode(self) -> np.ndarray:
        encoded_message = np.matmul(self.message, self.public_key) % 2
        return (encoded_message + self.error_vector) % 2

    def get_message(self) -> np.ndarray:
        return self.message

    def get_encrypted(self) -> np.ndarray:
        return self.encoded_message


class Decoder:
    def __init__(
        self,
        encoded_message: np.ndarray,
        invertible_matrix: np.ndarray,
        permutation_matrix: np.ndarray,
        parity_check_matrix: np.ndarray,
        original_message: np.ndarray,
    ):
        self.encoded_message = encoded_message
        self.invertible_matrix = invertible_matrix
        self.permutation_matrix = permutation_matrix
        self.parity_check_matrix = parity_check_matrix
        self.original_message = original_message
        self.decrypted_message = self.decrypt()
        self.is_correct = self.original_message == self.decrypted_message

    def decrypt(self) -> np.ndarray:
        perm_inv = np.linalg.inv(self.permutation_matrix)
        inv_matrix = np.linalg.inv(self.invertible_matrix)
        encoded_permuted = np.matmul(self.encoded_message, perm_inv)
        corrected_message = self.correct_errors(encoded_permuted)
        decrypted_message = np.matmul(corrected_message, inv_matrix) % 2
        return decrypted_message

    def correct_errors(self, encoded_permuted: np.ndarray) -> np.ndarray:
        parity = np.matmul(encoded_permuted, np.transpose(self.parity_check_matrix)) % 2
        parity_bits = np.ma.size(parity, 0)
        parity_total = sum(2**i * parity[i] for i in range(parity_bits))
        if int((parity_total - 1)) & int(parity_total) == 0:
            return encoded_permuted[0 : (encoded_permuted.size - parity_bits)]
        else:
            error_message = encoded_permuted
            error_bit = int(parity_total - math.ceil(np.log2(parity_total)) - 1)
            error_message[error_bit] = 1 - error_message[error_bit]
            return error_message[0 : (encoded_permuted.size - parity_bits)]


def split_string_into_blocks(input_string: list[str]) -> list[list[int]]:
    current_block = ""
    blocks = []
    for char in input_string:
        char_binary = bin(int(char, 16))[2:].zfill(16)
        current_block += char_binary
    block = []
    for bit in current_block:
        if len(block) == 4:
            blocks.append(block)
            block = []
        block.append(int(bit))
    blocks.append(block)
    return blocks


def blocks_into_string(blocks: list[list[int]]) -> str:
    proto_string = "".join(str(int(bit)) for block in blocks for bit in block)
    string = ""
    for i in range(0, len(proto_string), 16):
        delta_string = proto_string[i : i + 16]
        string += chr(int(hex(int(delta_string, 2)), 16))
    return string


def main() -> None:
    with open("input.txt", "r", encoding="utf8") as file:
        source_text = file.read()
    binary_text = [hex(ord(elem)) for elem in source_text]
    blocks = split_string_into_blocks(binary_text)

    key_gen = HammingKeyGenerator(3)
    public_key = key_gen.public_key

    encoded_list = []
    original_list = []
    for block in blocks:
        encoder = Encoder(np.array(block), public_key)
        message = encoder.get_message()
        encrypted = encoder.get_encrypted()
        encoded_list.append(encrypted)
        original_list.append(message)

    decoded_list = []
    for encoded_block, original_block in zip(encoded_list, original_list):
        decoder = Decoder(
            encoded_block,
            key_gen.invertible_matrix,
            key_gen.permutation_matrix,
            key_gen.parity_check_matrix,
            original_block,
        )
        decoded_list.append(decoder.decrypted_message)

    decrypted_string = blocks_into_string(decoded_list)
    encrypted_string = "".join(
        ["".join(map(str, map(int, sublist))) for sublist in encoded_list]
    )

    with open("encrypted.txt", "w", encoding="utf8") as file:
        file.write(encrypted_string)
    with open("decrypted.txt", "w", encoding="utf8") as file:
        file.write(decrypted_string)


if __name__ == "__main__":
    main()
