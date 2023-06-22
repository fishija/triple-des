import textwrap
import random
import sys

from src.tables import *


def random_binary_string(length):
    binary_string = "".join(str(random.randint(0, 1)) for _ in range(length))
    return binary_string


def str_to_hex(plain_text: str) -> str:
    plain_text = plain_text.encode()
    return plain_text.hex()


def hex_to_binary(hex_text: str) -> str:
    to_ret = ""
    for ht in hex_text:
        to_ret += bin(int(ht, 16))[2:].zfill(4)

    return to_ret


def binary_to_hex(binary_text: str) -> str:
    num = int(binary_text, 2)
    hex_num = hex(num)

    return hex_num


def binary_to_str(binary_text: str) -> str:
    return "".join([chr(int(i, 2)) for i in binary_text])


def permutation(binary_text, permutation_array):
    permutation = ""
    for val in permutation_array:
        permutation += binary_text[val - 1]

    return permutation


def apply_Expansion(expansion_table, bits32):
    bits48 = ""
    for index in expansion_table:
        bits48 += bits32[index - 1]

    return bits48


def XOR(bits1, bits2):
    xor_result = ""
    for index in range(len(bits1)):
        if bits1[index] == bits2[index]:
            xor_result += "0"
        else:
            xor_result += "1"

    return xor_result


def split_in_6bits(XOR_48bits):
    list_of_6bits = textwrap.wrap(XOR_48bits, 6)

    return list_of_6bits


def get_first_and_last_bit(bits6):
    twobits = bits6[0] + bits6[-1]

    return twobits


def get_middle_four_bit(bits6):
    fourbits = bits6[1:5]

    return fourbits


def binary_to_decimal(binarybits):
    decimal = int(binarybits, 2)

    return decimal


def decimal_to_binary(decimal):
    binary4bits = bin(decimal)[2:].zfill(4)

    return binary4bits


def sbox_lookup(sboxcount, first_last, middle4):
    d_first_last = binary_to_decimal(first_last)
    d_middle = binary_to_decimal(middle4)

    sbox_value = SBOX[sboxcount][d_first_last][d_middle]

    return decimal_to_binary(sbox_value)


def split_in_half(keys_56bits):
    left_keys, right_keys = keys_56bits[:28], keys_56bits[28:]

    return left_keys, right_keys


def circular_left_shift(bits, numberofbits):
    shiftedbits = bits[numberofbits:] + bits[:numberofbits]

    return shiftedbits


def create_subkeys(key_bits: str) -> list:
    left_bits, right_bits = split_in_half(key_bits)
    temp_shift_list = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    subkeys_to_ret = []

    for temp_shift in temp_shift_list:
        left_bits = circular_left_shift(left_bits, temp_shift)
        right_bits = circular_left_shift(right_bits, temp_shift)

        subkeys_to_ret.append(left_bits + right_bits)

    return subkeys_to_ret


def des_encrypt(binary_text: str, binary_key: str) -> str:
    a = ""

    # Manage binary_text len
    while len(binary_text) % 64:
        binary_text += "0"

    # Manage key
    str_binary_key = permutation(binary_key, PC_1)
    subkeys = create_subkeys(str_binary_key)

    for index, subkey in enumerate(subkeys):
        subkeys[index] = permutation(subkey, PC_2)

    # Split input text into 64 chunks
    binary_text_chunks = [
        binary_text[i : i + 64] for i in range(0, len(binary_text), 64)
    ]

    for input_text_binary_chunk in binary_text_chunks:
        input_text_binary_chunk = permutation(input_text_binary_chunk, IP)

        L = input_text_binary_chunk[: int(len(input_text_binary_chunk) / 2)]
        R = input_text_binary_chunk[int(len(input_text_binary_chunk) / 2) :]

        for subkey in subkeys:
            tmp = R
            R = apply_Expansion(E, R)
            R = XOR(R, subkey)

            temp = ""
            for index, bits_6 in enumerate(split_in_6bits(R)):
                first_last = get_first_and_last_bit(bits_6)  # '10' -> 2
                middle4 = get_middle_four_bit(bits_6)  # '0000' -> 0
                temp += sbox_lookup(index, first_last, middle4)

            temp = permutation(temp, P)
            R = XOR(temp, L)

            L = tmp

        RL = R + L
        RL = permutation(RL, FP)
        a += RL

    return a


def des_decrypt(binary_text: str, binary_key: int) -> str:
    a = ""

    # Manage binary_text len
    while len(binary_text) % 64:
        binary_text += "0"

    # Manage key
    str_binary_key = permutation(binary_key, PC_1)
    subkeys = create_subkeys(str_binary_key)

    for index, subkey in enumerate(subkeys):
        subkeys[index] = permutation(subkey, PC_2)

    # Split input text into 64 chunks
    binary_text_chunks = [
        binary_text[i : i + 64] for i in range(0, len(binary_text), 64)
    ]

    for input_text_binary_chunk in binary_text_chunks:
        input_text_binary_chunk = permutation(input_text_binary_chunk, IP)

        L = input_text_binary_chunk[: int(len(input_text_binary_chunk) / 2)]
        R = input_text_binary_chunk[int(len(input_text_binary_chunk) / 2) :]

        # print(f"M = {binary_text_chunks}\nL = {binary_to_hex(L)}\nR = {binary_to_hex(R)}\nK+ = {str_binary_key}")

        for subkey in reversed(subkeys):
            tmp = R
            R = apply_Expansion(E, R)
            R = XOR(R, subkey)

            temp = ""
            for index, bits_6 in enumerate(split_in_6bits(R)):
                first_last = get_first_and_last_bit(bits_6)  # '10' -> 2
                middle4 = get_middle_four_bit(bits_6)  # '0000' -> 0
                temp += sbox_lookup(index, first_last, middle4)

            temp = permutation(temp, P)
            R = XOR(temp, L)

            L = tmp

        RL = R + L
        RL = permutation(RL, FP)
        a += RL

    return a


def triple_des_encrypt(plain_text: str, K1: str, K2: str) -> str:
    """
    M - plain_text
    K1 - klucz 64 bity
    K2 - klucz 64 bity

    X = des_encrypt(M, K1)
    Y = des_decrypt(X, K2)
    encrypted = des_encrypt(Y, K1)
    """
    X = des_encrypt(plain_text, K1)
    Y = des_decrypt(X, K2)
    encrypted = des_encrypt(Y, K1)

    return encrypted


def triple_des_decrypt(ciphertext: str, K1: str, K2: str) -> str:
    """
    M - ciphertext
    K1 - klucz 64 bity
    K2 - klucz 64 bity

    X = des_decrypt(M, K1)
    Y = des_encrypt(X, K2)
    decrypted = des_decrypt(Y, K1)
    """
    X = des_decrypt(ciphertext, K1)
    Y = des_encrypt(X, K2)
    decrypted = des_decrypt(Y, K1)

    return decrypted


if __name__ == "__main__":
    from tables import *
    import random
    import codecs

    # Text in hex
    pt = "abcdefghijklmnopqrstuvwqz"
    print("Plain txt: ", pt)

    pt = str_to_hex(pt)
    print("Hex txt: ", pt)
    pt = hex_to_binary(pt)

    # Key in hex
    key = "0E329232EA6D0D73"
    print("Key: ", key)
    key = hex_to_binary(key)

    # Encrypt with des
    encrypted = des_encrypt(pt, key)

    # Decrypt with des
    decrypted = des_decrypt(encrypted, key)
    print("Decrypted: ", codecs.decode(binary_to_hex(decrypted)[2:], "hex").decode())

    sys.exit()
