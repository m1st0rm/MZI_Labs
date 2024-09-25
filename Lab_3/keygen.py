import random

from sympy import isprime


def key_gen(n):
    while True:
        prime_candidate = random.randint(10 ** (n - 1), 10**n - 1)

        if isprime(prime_candidate) and prime_candidate % 4 == 3:
            return prime_candidate


prime1 = key_gen(20)
prime2 = key_gen(20)

product = prime1 * prime2

with open("keys_generated.txt", "w", encoding="utf-8") as f:
    f.write(f"Private key p: {prime1}\n")
    f.write(f"Private key q: {prime2}\n")
    f.write(f"Public key n: {product}\n")

print("The keys have been generated successfully and stored in keys_generated.txt.")
