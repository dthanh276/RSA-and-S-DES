# INFO3006 Practical Assignment
# Task 1 - S-DES
# Implements S-DES encryption and decryption

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


# does permutation using the given table
def perm(bits, table):
    result = ""

    for i in table:
        result += bits[i - 1]

    return result


# circular left shift
def left_shift(bits, n):
    return bits[n:] + bits[:n]


# xor two binary strings
def xor(a, b):
    result = ""

    for i in range(len(a)):
        if a[i] == b[i]:
            result += "0"
        else:
            result += "1"

    return result


# makes K1 and K2 from the 10-bit key
def make_keys(key):
    # apply P10 before splitting the key
    key = perm(key, P10)

    left = key[:5]
    right = key[5:]

    # shift both halves left once for K1
    left = left_shift(left, 1)
    right = left_shift(right, 1)

    k1 = perm(left + right, P8)

    # shift both halves two more times for K2
    left = left_shift(left, 2)
    right = left_shift(right, 2)

    k2 = perm(left + right, P8)

    return k1, k2


# gets a value from an S-box
def use_sbox(bits, box):
    # first and fourth bits give the row
    row = int(bits[0] + bits[3], 2)

    # middle two bits give the column
    col = int(bits[1] + bits[2], 2)

    num = box[row][col]

    return format(num, "02b")


# S-DES F function
def f(right, key):
    # expand 4 bits into 8 bits
    temp = perm(right, EP)

    # xor with the round key
    temp = xor(temp, key)

    left = temp[:4]
    right = temp[4:]

    # use S0 for the left half and S1 for the right half
    a = use_sbox(left, S0)
    b = use_sbox(right, S1)

    temp = a + b

    return perm(temp, P4)


# fk round function
def fk(bits, key):
    left = bits[:4]
    right = bits[4:]

    temp = f(right, key)

    left = xor(left, temp)

    return left + right


# swaps the two 4-bit halves
def swap(bits):
    return bits[4:] + bits[:4]


# encrypts an 8-bit plaintext
def encrypt(text, key):
    k1, k2 = make_keys(key)

    text = perm(text, IP)

    text = fk(text, k1)

    text = swap(text)

    text = fk(text, k2)

    text = perm(text, IP_INV)

    return text


# decrypts using the round keys in reverse order
def decrypt(text, key):
    k1, k2 = make_keys(key)

    text = perm(text, IP)

    text = fk(text, k2)

    text = swap(text)

    text = fk(text, k1)

    text = perm(text, IP_INV)

    return text


# checks that input has the correct length and only contains 0 and 1
def get_bits(message, size):
    while True:
        value = input(message)

        if len(value) == size and all(x in "01" for x in value):
            return value

        print("Invalid input, try again.")


def main():
    while True:
        print("\nS-DES")
        print("1. Encrypt")
        print("2. Decrypt")
        print("0. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            text = get_bits("Enter 8-bit plaintext: ", 8)
            key = get_bits("Enter 10-bit key: ", 10)

            k1, k2 = make_keys(key)

            answer = encrypt(text, key)

            print("K1:", k1)
            print("K2:", k2)
            print("Ciphertext:", answer)

        elif choice == "2":
            text = get_bits("Enter 8-bit ciphertext: ", 8)
            key = get_bits("Enter 10-bit key: ", 10)

            k1, k2 = make_keys(key)

            answer = decrypt(text, key)

            print("K1:", k1)
            print("K2:", k2)
            print("Plaintext:", answer)

        elif choice == "0":
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()