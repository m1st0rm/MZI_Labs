import sys
from typing import List


TABLE: List[List[int]] = [
    [
        0xB1,
        0x94,
        0xBA,
        0xC8,
        0x0A,
        0x08,
        0xF5,
        0x3B,
        0x36,
        0x6D,
        0x00,
        0x8E,
        0x58,
        0x4A,
        0x5D,
        0xE4,
    ],
    [
        0x85,
        0x04,
        0xFA,
        0x9D,
        0x1B,
        0xB6,
        0xC7,
        0xAC,
        0x25,
        0x2E,
        0x72,
        0xC2,
        0x02,
        0xFD,
        0xCE,
        0x0D,
    ],
    [
        0x5B,
        0xE3,
        0xD6,
        0x12,
        0x17,
        0xB9,
        0x61,
        0x81,
        0xFE,
        0x67,
        0x86,
        0xAD,
        0x71,
        0x6B,
        0x89,
        0x0B,
    ],
    [
        0x5C,
        0xB0,
        0xC0,
        0xFF,
        0x33,
        0xC3,
        0x56,
        0xB8,
        0x35,
        0xC4,
        0x05,
        0xAE,
        0xD8,
        0xE0,
        0x7F,
        0x99,
    ],
    [
        0xE1,
        0x2B,
        0xDC,
        0x1A,
        0xE2,
        0x82,
        0x57,
        0xEC,
        0x70,
        0x3F,
        0xCC,
        0xF0,
        0x95,
        0xEE,
        0x8D,
        0xF1,
    ],
    [
        0xC1,
        0xAB,
        0x76,
        0x38,
        0x9F,
        0xE6,
        0x78,
        0xCA,
        0xF7,
        0xC6,
        0xF8,
        0x60,
        0xD5,
        0xBB,
        0x9C,
        0x4F,
    ],
    [
        0xF3,
        0x3C,
        0x65,
        0x7B,
        0x63,
        0x7C,
        0x30,
        0x6A,
        0xDD,
        0x4E,
        0xA7,
        0x79,
        0x9E,
        0xB2,
        0x3D,
        0x31,
    ],
    [
        0x3E,
        0x98,
        0xB5,
        0x6E,
        0x27,
        0xD3,
        0xBC,
        0xCF,
        0x59,
        0x1E,
        0x18,
        0x1F,
        0x4C,
        0x5A,
        0xB7,
        0x93,
    ],
    [
        0xE9,
        0xDE,
        0xE7,
        0x2C,
        0x8F,
        0x0C,
        0x0F,
        0xA6,
        0x2D,
        0xDB,
        0x49,
        0xF4,
        0x6F,
        0x73,
        0x96,
        0x47,
    ],
    [
        0x06,
        0x07,
        0x53,
        0x16,
        0xED,
        0x24,
        0x7A,
        0x37,
        0x39,
        0xCB,
        0xA3,
        0x83,
        0x03,
        0xA9,
        0x8B,
        0xF6,
    ],
    [
        0x92,
        0xBD,
        0x9B,
        0x1C,
        0xE5,
        0xD1,
        0x41,
        0x01,
        0x54,
        0x45,
        0xFB,
        0xC9,
        0x5E,
        0x4D,
        0x0E,
        0xF2,
    ],
    [
        0x68,
        0x20,
        0x80,
        0xAA,
        0x22,
        0x7D,
        0x64,
        0x2F,
        0x26,
        0x87,
        0xF9,
        0x34,
        0x90,
        0x40,
        0x55,
        0x11,
    ],
    [
        0xBE,
        0x32,
        0x97,
        0x13,
        0x43,
        0xFC,
        0x9A,
        0x48,
        0xA0,
        0x2A,
        0x88,
        0x5F,
        0x19,
        0x4B,
        0x09,
        0xA1,
    ],
    [
        0x7E,
        0xCD,
        0xA4,
        0xD0,
        0x15,
        0x44,
        0xAF,
        0x8C,
        0xA5,
        0x84,
        0x50,
        0xBF,
        0x66,
        0xD2,
        0xE8,
        0x8A,
    ],
    [
        0xA2,
        0xD7,
        0x46,
        0x52,
        0x42,
        0xA8,
        0xDF,
        0xB3,
        0x69,
        0x74,
        0xC5,
        0x51,
        0xEB,
        0x23,
        0x29,
        0x21,
    ],
    [
        0xD4,
        0xEF,
        0xD9,
        0xB4,
        0x3A,
        0x62,
        0x28,
        0x75,
        0x91,
        0x14,
        0x10,
        0xEA,
        0x77,
        0x6C,
        0xDA,
        0x1D,
    ],
]


class STB:
    def __init__(self, key: int) -> None:
        count = self.get_key_chunks_counts(key)
        self.tmp_keys: List[int] = []

        for i in range(count):
            self.tmp_keys.append(key & 0xFFFF)
            key >>= 32

        if count == 4:
            self.tmp_keys.extend(self.tmp_keys[:])
        elif count == 6:
            self.tmp_keys.extend(
                [
                    self.tmp_keys[0] ^ self.tmp_keys[1] ^ self.tmp_keys[2],
                    self.tmp_keys[3] ^ self.tmp_keys[4] ^ self.tmp_keys[5],
                ]
            )

        self.K: List[int] = []
        for _ in range(8):
            self.K.extend(self.tmp_keys[:])

    def get_key_chunks_counts(self, key: int) -> int:
        length = key.bit_length()
        if 256 >= length > 192:
            return 8
        elif 192 >= length > 128:
            return 6
        else:
            return 4

    def rot_hi(self, u: int) -> int:
        if u < 1 << 31:
            return (2 * u) % (1 << 32)
        else:
            return (2 * u + 1) % (1 << 32)

    def rot_hi_r(self, u: int, r: int) -> int:
        result = u
        for _ in range(r):
            result = self.rot_hi(result)
        return result

    def square_plus(self, u: int, v: int) -> int:
        return (u + v) % (1 << 32)

    def square_minus(self, u: int, v: int) -> int:
        return (u - v) % (1 << 32)

    def G(self, r: int, word: int) -> int:
        mask = (1 << 8) - 1
        final = 0
        for i in range(4):
            part = word & mask
            word >>= 8
            right = part & 0x0F
            left = (part & 0xF0) >> 4
            result = TABLE[left][right]
            result <<= 8 * i
            final += result
        return self.rot_hi_r(final, r)

    def encrypt_block(self, X: int) -> int:
        if self.get_key_chunks_counts(X) != 4:
            raise ValueError()
        d = X & 0xFFFFFFFF
        X >>= 32
        c = X & 0xFFFFFFFF
        X >>= 32
        b = X & 0xFFFFFFFF
        X >>= 32
        a = X

        for i in range(1, 9):
            b = b ^ self.G(5, self.square_plus(a, self.K[7 * i - 7]))
            c = c ^ self.G(21, self.square_plus(d, self.K[7 * i - 6]))
            a = self.square_minus(a, self.G(13, self.square_plus(b, self.K[7 * i - 5])))
            e = self.G(
                21, self.square_plus(self.square_plus(b, c), self.K[7 * i - 4])
            ) ^ (i % (2**32))
            b = self.square_plus(b, e)
            c = self.square_minus(c, e)
            d = self.square_plus(d, self.G(13, self.square_plus(c, self.K[7 * i - 3])))
            b = b ^ self.G(21, self.square_plus(a, self.K[7 * i - 2]))
            c = c ^ self.G(5, self.square_plus(d, self.K[7 * i - 1]))
            a, b = b, a
            c, d = d, c
            b, c = c, b

        return (b << 96) + (d << 64) + (a << 32) + c

    def decrypt_block(self, X: int) -> int:
        if self.get_key_chunks_counts(X) != 4:
            raise ValueError()
        d = X & 0xFFFFFFFF
        X >>= 32
        c = X & 0xFFFFFFFF
        X >>= 32
        b = X & 0xFFFFFFFF
        X >>= 32
        a = X

        for i in range(8, 0, -1):
            b = b ^ self.G(5, self.square_plus(a, self.K[7 * i - 1]))
            c = c ^ self.G(21, self.square_plus(d, self.K[7 * i - 2]))
            a = self.square_minus(a, self.G(13, self.square_plus(b, self.K[7 * i - 3])))
            e = self.G(
                21, self.square_plus(self.square_plus(b, c), self.K[7 * i - 4])
            ) ^ (i % (2**32))
            b = self.square_plus(b, e)
            c = self.square_minus(c, e)
            d = self.square_plus(d, self.G(13, self.square_plus(c, self.K[7 * i - 5])))
            b = b ^ self.G(21, self.square_plus(a, self.K[7 * i - 6]))
            c = c ^ self.G(5, self.square_plus(d, self.K[7 * i - 7]))
            a, b = b, a
            c, d = d, c
            a, d = d, a

        return (c << 96) + (a << 64) + (d << 32) + b

    def split_message(self, message: int) -> List[int]:
        chunks: List[int] = []
        while message:
            chunk = message & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            chunks.append(chunk)
            message >>= 128
        return chunks

    def join_message(self, chunks: List[int]) -> int:
        answer = 0
        for chunk in chunks:
            answer <<= 128
            answer += chunk
        return answer

    def encrypt(self, message: str) -> bytes:
        plain_msg = int.from_bytes(message.encode(), "big")
        chunks = self.split_message(plain_msg)
        results = self.encrypt_block_plain(chunks)
        answer = self.join_message(results)
        return answer.to_bytes((answer.bit_length() + 7) // 8, "big")

    def decrypt(self, message: bytes) -> str:
        plain_msg = int.from_bytes(message, "big")
        chunks = reversed(self.split_message(plain_msg))
        results = self.decrypt_block_plain(chunks)
        answer = self.join_message(reversed(results))
        return answer.to_bytes((answer.bit_length() + 7) // 8, "big").decode()

    def encrypt_block_plain(self, chunks: List[int]) -> List[int]:
        results: List[int] = []
        for X in chunks:
            Y = self.encrypt_block(X)
            results.append(Y)
        return results

    def decrypt_block_plain(self, chunks: List[int]) -> List[int]:
        results: List[int] = []
        for X in chunks:
            Y = self.decrypt_block(X)
            results.append(Y)
        return results


def main() -> None:
    try:
        with open("input.txt", "r") as file:
            data = file.read()
        key = int.from_bytes("qwertyqwertyqweerty".encode(), "big")
        s = STB(key)
        encrypted_text = s.encrypt(data)

        with open("encrypted.txt", "wb") as file:
            file.write(encrypted_text)

        with open("encrypted.txt", "rb") as file:
            encrypted_data = file.read()
        decrypted_text = s.decrypt(encrypted_data)

        with open("decrypted.txt", "w") as file:
            file.write(decrypted_text)
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
