# INFO3006 Practical Assignment
# Task 2 - RSA
# Implements RSA encryption and decryption using manual and auto modes

import random


# checks if a number is prime
def is_prime(n):
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    i = 3

    while i * i <= n:
        if n % i == 0:
            return False

        i += 2

    return True


# greatest common divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b

    return a


# extended euclidean algorithm
# used to help find the modular inverse
def egcd(a, b):
    if b == 0:
        return a, 1, 0

    g, x1, y1 = egcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


# finds the modular inverse
# for RSA this finds d from e, or e from d
def inverse(a, mod):
    g, x, y = egcd(a, mod)

    if g != 1:
        return None

    return x % mod


# square and multiply algorithm
def square_multiply(a, b, n):
    result = 1

    a = a % n

    # convert the exponent to binary
    bits = bin(b)[2:]

    # process the exponent bits from left to right
    for bit in bits:
        result = (result * result) % n

        # multiply by a if the current bit is 1
        if bit == "1":
            result = (result * a) % n

    return result


# checks e or d
def valid_exp(x, phi):
    if x <= 1 or x >= phi:
        return False

    if gcd(x, phi) != 1:
        return False

    return True


# gets all possible exponent values
def get_exps(phi):
    values = []

    for i in range(2, phi):
        if gcd(i, phi) == 1:
            values.append(i)

    return values


# checks that p and q can be used for RSA
def valid_pq(p, q):
    if p < 2 or p > 100:
        return False

    if q < 2 or q > 100:
        return False

    if p == q:
        return False

    if not is_prime(p) or not is_prime(q):
        return False

    phi = (p - 1) * (q - 1)

    # there must be at least one valid exponent
    if len(get_exps(phi)) == 0:
        return False

    return True


# randomly chooses valid p and q
def random_pq():
    primes = []

    for i in range(2, 101):
        if is_prime(i):
            primes.append(i)

    # keep trying until a valid RSA pair is found
    while True:
        p, q = random.sample(primes, 2)

        if valid_pq(p, q):
            return p, q


# gets an integer from the user
def get_int(message):
    while True:
        try:
            return int(input(message))

        except ValueError:
            print("Please enter a number.")


# gets p and q manually
def get_pq():
    while True:
        p = get_int("Enter p: ")
        q = get_int("Enter q: ")

        if valid_pq(p, q):
            return p, q

        print(
            "Invalid p and q. Enter different primes from 2 to 100 "
            "that allow a valid RSA exponent."
        )


# gets e or d
def get_exp(message, phi):
    while True:
        x = get_int(message)

        if valid_exp(x, phi):
            return x

        print("Invalid value.")


# gets plaintext or ciphertext
def get_num(message, n):
    while True:
        x = get_int(message)

        if 0 <= x < n:
            return x

        print("Value must be from 0 to", n - 1)


# lets the user choose manual or random input
def choose_input(name):
    while True:
        print("\n1. Enter", name, "manually")
        print("2. Generate", name, "randomly")

        choice = input("Choice: ")

        if choice == "1" or choice == "2":
            return choice

        print("Invalid choice.")


# shows the main RSA values
def show_values(p, q, e, d):
    n = p * q
    phi = (p - 1) * (q - 1)

    print("\np =", p)
    print("q =", q)
    print("n =", n)
    print("phi(n) =", phi)
    print("e =", e)
    print("d =", d)


# manual encryption
def manual_encrypt():
    p, q = get_pq()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = get_exp("Enter e: ", phi)

    # d is the modular inverse of e
    d = inverse(e, phi)

    m = get_num("Enter plaintext m: ", n)

    c = square_multiply(m, e, n)

    show_values(p, q, e, d)

    print("Plaintext =", m)
    print("Ciphertext =", c)


# manual decryption
def manual_decrypt():
    p, q = get_pq()

    n = p * q
    phi = (p - 1) * (q - 1)

    d = get_exp("Enter d: ", phi)

    # e is the modular inverse of d
    e = inverse(d, phi)

    c = get_num("Enter ciphertext c: ", n)

    m = square_multiply(c, d, n)

    show_values(p, q, e, d)

    print("Ciphertext =", c)
    print("Plaintext =", m)


# automatic encryption
def auto_encrypt():
    p, q = random_pq()

    n = p * q
    phi = (p - 1) * (q - 1)

    print("\nRandom p =", p)
    print("Random q =", q)

    choice = choose_input("e")

    if choice == "1":
        e = get_exp("Enter e: ", phi)

    else:
        e = random.choice(get_exps(phi))
        print("Random e =", e)

    d = inverse(e, phi)

    choice = choose_input("plaintext")

    if choice == "1":
        m = get_num("Enter plaintext m: ", n)

    else:
        m = random.randint(0, n - 1)
        print("Random plaintext =", m)

    c = square_multiply(m, e, n)

    show_values(p, q, e, d)

    print("Plaintext =", m)
    print("Ciphertext =", c)


# automatic decryption
def auto_decrypt():
    p, q = random_pq()

    n = p * q
    phi = (p - 1) * (q - 1)

    print("\nRandom p =", p)
    print("Random q =", q)

    choice = choose_input("d")

    if choice == "1":
        d = get_exp("Enter d: ", phi)

    else:
        d = random.choice(get_exps(phi))
        print("Random d =", d)

    e = inverse(d, phi)

    choice = choose_input("ciphertext")

    if choice == "1":
        c = get_num("Enter ciphertext c: ", n)

    else:
        c = random.randint(0, n - 1)
        print("Random ciphertext =", c)

    m = square_multiply(c, d, n)

    show_values(p, q, e, d)

    print("Ciphertext =", c)
    print("Plaintext =", m)


def main():
    while True:
        print("\nRSA")
        print("1. Encrypt")
        print("2. Decrypt")
        print("0. Exit")

        choice = input("Enter choice: ")

        if choice == "0":
            break

        if choice != "1" and choice != "2":
            print("Invalid choice.")
            continue

        print("\n1. Manual")
        print("2. Auto")

        mode = input("Enter choice: ")

        if mode != "1" and mode != "2":
            print("Invalid choice.")
            continue

        if choice == "1":
            if mode == "1":
                manual_encrypt()
            else:
                auto_encrypt()

        else:
            if mode == "1":
                manual_decrypt()
            else:
                auto_decrypt()


if __name__ == "__main__":
    main()