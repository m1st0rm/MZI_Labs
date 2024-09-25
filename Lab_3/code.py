import os
import sys
from typing import List

from sympy import isprime


class RabinCryptoSystem:
    def __init__(self):
        self.decrypted_bytes = None
        self.encrypted_bytes = None

    def read_bytes(self, file_path: str, mode: str) -> None:
        if mode == "e":
            with open(file_path, mode="rb") as f:
                self.decrypted_bytes = b"\x01" + f.read()
        else:
            with open(file_path, mode="rb") as f:
                self.encrypted_bytes = f.read()

    def write_bytes(self, bytes_to_write: bytes, mode: str) -> None:
        if mode == "e":
            with open("encrypted.txt", mode="wb") as f:
                f.write(bytes_to_write)
        else:
            with open("decrypted.txt", mode="wb") as f:
                f.write(bytes_to_write)

    def key_length_checker(self, key: int, msg: int, mode: str) -> None:
        if key <= msg:
            if mode == "e":
                raise Exception(
                    "Error: Public key must be greater than message in integer representation."
                )
            else:
                raise Exception(
                    "Error: Product of private keys must be greater than decrypted message in integer representation."
                )

    @staticmethod
    def key_criteria_checker(key: List[int]) -> None:
        critetia = (key[0] % 4 == 3 and isprime(key[0])) and (
            key[1] % 4 == 3 and isprime(key[1])
        )
        if not critetia:
            raise Exception(
                "Error: One or more private keys do not meet the private key criteria."
            )

    @staticmethod
    def extended_gcd(p: int, q: int) -> List[int]:
        x0, x1, y0, y1 = 1, 0, 0, 1

        while q != 0:
            quotient = p // q
            p, q = q, p % q

            x0, x1 = x1, x0 - quotient * x1
            y0, y1 = y1, y0 - quotient * y1

        return [x0, y0]

    @staticmethod
    def check_first_byte(n: int) -> bool:
        byte_length = (n.bit_length() + 7) // 8
        byte_repr = n.to_bytes(byte_length, byteorder="big")

        return byte_repr[0:1] == b"\x01"

    @staticmethod
    def remove_first_byte(n: int) -> bytes:
        byte_length = (n.bit_length() + 7) // 8
        byte_repr = n.to_bytes(byte_length, byteorder="big")

        return byte_repr[1:]

    def encrypt_message(self, file_path: str, pub_key: int) -> None:
        self.read_bytes(file_path, mode="e")

        message_integer = int.from_bytes(self.decrypted_bytes, byteorder="big")

        try:
            self.key_length_checker(pub_key, message_integer, mode="e")
        except Exception as e:
            print(e)
            return

        encrypted_message_integer = (message_integer**2) % pub_key
        encrypted_message_byte_length = (encrypted_message_integer.bit_length() + 7) // 8
        encrypted_message_byte_representation = encrypted_message_integer.to_bytes(
            encrypted_message_byte_length, byteorder="big"
        )

        self.write_bytes(encrypted_message_byte_representation, mode="e")

        print("Success: Encrypted message stored in ecnrypted.txt.")

    def decrypt_message(self, file_path: str, private_key: List[int]) -> None:
        self.read_bytes(file_path, mode="d")

        message_integer = int.from_bytes(self.encrypted_bytes, byteorder="big")

        try:
            self.key_criteria_checker(private_key)
        except Exception as e:
            print(e)
            return

        message_square_root_modulo_p = pow(
            message_integer, ((private_key[0] + 1) // 4), private_key[0]
        )
        message_square_root_modulo_q = pow(
            message_integer, ((private_key[1] + 1) // 4), private_key[1]
        )

        bezu_ratio_coefficients = self.extended_gcd(private_key[0], private_key[1])
        public_key = private_key[0] * private_key[1]

        candidate_1 = (
            (bezu_ratio_coefficients[0] * private_key[0] * message_square_root_modulo_q)
            + (bezu_ratio_coefficients[1] * private_key[1] * message_square_root_modulo_p)
        ) % public_key
        candidate_2 = public_key - candidate_1
        candidate_3 = (
            (bezu_ratio_coefficients[0] * private_key[0] * message_square_root_modulo_q)
            - (bezu_ratio_coefficients[1] * private_key[1] * message_square_root_modulo_p)
        ) % public_key
        candidate_4 = public_key - candidate_3

        candidates = [candidate_1, candidate_2, candidate_3, candidate_4]
        filtered_candidates = [n for n in candidates if self.check_first_byte(n)]

        if not filtered_candidates:
            print("Error: Unable to decrypt message with specified private keys.")
            return

        self.write_bytes(self.remove_first_byte(filtered_candidates[0]), mode="d")

        print("Success: Decrypted message stored in decrypted.txt.")


def main():
    if len(sys.argv) < 4:
        print("Usage: python script.py <mode> <file_path> <key(s)>")
        return

    mode = sys.argv[1].lower()
    file_path = sys.argv[2]

    if not os.path.isfile(file_path) or not file_path.endswith(".txt"):
        print("Error: The file must exist and be a .txt file.")
        return

    rabin_system = RabinCryptoSystem()

    if mode == "e":
        if len(sys.argv) != 4:
            print("Error: Encryption mode requires exactly one key.")
            return
        try:
            public_key = int(sys.argv[3])
        except ValueError:
            print("Error: The public key must be an integer.")
            return

        rabin_system.encrypt_message(file_path, public_key)

    elif mode == "d":
        if len(sys.argv) != 5:
            print("Error: Decryption mode requires exactly two keys.")
            return
        try:
            private_keys = [int(sys.argv[3]), int(sys.argv[4])]
        except ValueError:
            print("Error: Both private keys must be integers.")
            return

        rabin_system.decrypt_message(file_path, private_keys)

    else:
        print("Error: Invalid mode. Use 'e' for encryption or 'd' for decryption.")


if __name__ == "__main__":
    main()
