import argparse
from random import randint

from asn import encode_file_signature, parse_file
from constants import *
from elliptic_curve import *
from gost_3411 import bin_to_hex_string, hex_bin, stribog
from sympy import gcd


curve = EllipticCurve(A, B)
P = Point(x, y)
Q = multiply(P, d, curve.a, p)


def generate_prime(q):

    while True:
        k = randint(1, q - 1)

        if gcd(k, q) == 1:
            return k


def add_sign(filename, data):

    hash = stribog(hex_bin(bin_to_hex_string(data)), 2).encode("utf-8")
    print(
        "[+] Hash: {0}".format(
            stribog(hex_bin(bin_to_hex_string(data)), 2).encode("utf-8")
        )
    )

    alpha = int.from_bytes(hash, byteorder="big")
    e = alpha % q
    if e == 0:
        e = 1

    while True:
        k = generate_prime(q)

        C = multiply(P, k, curve.a, p)
        r = C.x % q
        if r == 0:
            continue

        s = (r * d + k * e) % q
        if s == 0:
            continue

        encoded_bytes = encode_file_signature(Q, p, curve, P, q, r, s)

        with open(filename + ".sign", "wb") as sign:
            sign.write(encoded_bytes)

        return True


def sign(filename):
    with open(filename, "rb") as file:
        data = file.read()
    (
        print("[+] Success added signature")
        if add_sign(filename, data)
        else print("[-] Wrong")
    )


def verify_sign(filename, file_Signature):

    decoded_values = parse_file(file_Signature)

    s = decoded_values[-1]
    r = decoded_values[-2]
    q = decoded_values[-3]
    Q_x = decoded_values[0]
    Q_y = decoded_values[1]
    p = decoded_values[2]
    a = decoded_values[3]
    P_x = decoded_values[5]
    P_y = decoded_values[6]

    if r <= 0 or r >= q or s <= 0 or s >= q:
        print("[-] Invalid signature")

    with open(filename, "rb") as file:
        data = file.read()

    hash = stribog(hex_bin(bin_to_hex_string(data)), 2).encode("utf-8")

    alpha = int.from_bytes(hash, byteorder="big")
    e = alpha % q
    if e == 0:
        e = 1

    v = invert(e, q)

    z_1 = (s * v) % q
    z_2 = (-r * v) % q

    tmp_1 = multiply(Point(P_x, P_y), z_1, a, p)
    tmp_2 = multiply(Point(Q_x, Q_y), z_2, a, p)
    C = add(tmp_1, tmp_2, a, p)
    R = C.x % q

    return True if R == r else False


def createParser():

    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--sign", help="Add signature", action="store_true")
    parser.add_argument("-c", "--check", help="Check signature", action="store_true")
    parser.add_argument("--file", help="File")
    parser.add_argument("--signature", help="File_Signature")

    return parser


def main():

    parser = createParser()

    args = parser.parse_args()

    if args.sign:
        sign(args.file)

    if args.check:
        if verify_sign(args.file, args.signature):
            print("[+] Sign is correct")
        else:
            print("[-] Sign is incorrect")


if __name__ == "__main__":
    main()
