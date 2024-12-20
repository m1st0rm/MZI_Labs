import hashlib
import sys


class SHA1:
    def __init__(self):
        self.__H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def __str__(self):
        return "".join((hex(h)[2:]).rjust(8, "0") for h in self.__H)

    @staticmethod
    def __ROTL(n, x, w=32):
        return (x << n) | (x >> w - n)

    @staticmethod
    def __padding(stream):
        l = len(stream)
        hl = [
            int((hex(l * 8)[2:]).rjust(16, "0")[i : i + 2], 16) for i in range(0, 16, 2)
        ]

        l0 = (56 - l) % 64
        if not l0:
            l0 = 64

        if isinstance(stream, str):
            stream += chr(0b10000000)
            stream += chr(0) * (l0 - 1)
            for a in hl:
                stream += chr(a)
        elif isinstance(stream, bytes):
            stream += bytes([0b10000000])
            stream += bytes(l0 - 1)
            stream += bytes(hl)

        return stream

    @staticmethod
    def __prepare(stream):
        M = []
        n_blocks = len(stream) // 64

        stream = bytearray(stream)

        for i in range(n_blocks):
            m = []

            for j in range(16):
                n = 0
                for k in range(4):
                    n <<= 8
                    n += stream[i * 64 + j * 4 + k]

                m.append(n)

            M.append(m[:])

        return M

    @staticmethod
    def __debug_print(t, a, b, c, d, e):
        print(
            "t = {0} : \t".format(t),
            (hex(a)[2:]).rjust(8, "0"),
            (hex(b)[2:]).rjust(8, "0"),
            (hex(c)[2:]).rjust(8, "0"),
            (hex(d)[2:]).rjust(8, "0"),
            (hex(e)[2:]).rjust(8, "0"),
        )

    def __process_block(self, block):
        MASK = 2**32 - 1

        W = block[:]
        for t in range(16, 80):
            W.append(SHA1.__ROTL(1, (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16])) & MASK)

        a, b, c, d, e = self.__H[:]

        for t in range(80):
            if t <= 19:
                K = 0x5A827999
                f = (b & c) ^ (~b & d)
            elif t <= 39:
                K = 0x6ED9EBA1
                f = b ^ c ^ d
            elif t <= 59:
                K = 0x8F1BBCDC
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                K = 0xCA62C1D6
                f = b ^ c ^ d

            T = (SHA1.__ROTL(5, a) + f + e + K + W[t]) & MASK
            e = d
            d = c
            c = SHA1.__ROTL(30, b) & MASK
            b = a
            a = T

        self.__H[0] = (a + self.__H[0]) & MASK
        self.__H[1] = (b + self.__H[1]) & MASK
        self.__H[2] = (c + self.__H[2]) & MASK
        self.__H[3] = (d + self.__H[3]) & MASK
        self.__H[4] = (e + self.__H[4]) & MASK

    def update(self, stream):
        stream = SHA1.__padding(stream)
        stream = SHA1.__prepare(stream)

        for block in stream:
            self.__process_block(block)

    def digest(self):
        pass

    def hexdigest(self):
        s = ""
        for h in self.__H:
            s += (hex(h)[2:]).rjust(8, "0")
        return s


def usage():
    print("Usage: python SHA1.py <file> [<file> ...]")
    sys.exit()


def sha1_file(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()


def main():
    if len(sys.argv) < 2:
        usage()

    for filename in sys.argv[1:]:
        try:
            with open(filename, "rb") as f:
                content = f.read()

        except:
            print('ERROR: Input file "{0}" cannot be read.'.format(filename))

        else:
            hash_value = sha1_file(filename)
            print(f"{hash_value} SHA-1 из библиотеки")
            h = SHA1()
            h.update(content)
            hex_sha = h.hexdigest()
            print("{0}  {1}".format(hex_sha, filename))


if __name__ == "__main__":
    main()
