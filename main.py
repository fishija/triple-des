from src.functions import (
    random_binary_string,
    str_to_hex,
    hex_to_binary,
    binary_to_hex,
    triple_des_encrypt,
    triple_des_decrypt,
)
import codecs
import sys


if __name__ == "__main__":
    print("Triple des implementation by Jakub Mikula.")
    print("Correctness can be verified at https://emvlab.org/descalc/")
    print("")

    while True:
        input_text_plain = input("Input text for encryption (enter to leave):")

        if not input_text_plain:
            sys.exit()

        input_text_hex = str_to_hex(input_text_plain)
        input_text_binary = hex_to_binary(input_text_hex)

        key_1 = random_binary_string(64)
        key_1_hex = binary_to_hex(key_1)[2:]
        key_2 = random_binary_string(64)
        key_2_hex = binary_to_hex(key_2)[2:]

        print(f"input_text_plain: {input_text_plain}")
        print(f"input_text_hex: {input_text_hex}")
        print(f"input_text_binary: {input_text_binary}")
        print()
        print(f"key_1: {key_1}")
        print(f"key_1_hex: {key_1_hex}")
        print(f"key_2: {key_2}")
        print(f"key_2_hex: {key_2_hex}")
        print()

        encrypted_binary = triple_des_encrypt(input_text_binary, key_1, key_2)
        encrypted_hex = binary_to_hex(encrypted_binary)[2:]

        print(f"encrypted_binary: {encrypted_binary}")
        print(f"encrypted_hex: {encrypted_hex}")
        print()

        decrypted_binary = triple_des_decrypt(encrypted_binary, key_1, key_2)
        decrypted_hex = binary_to_hex(decrypted_binary)[2:]
        decrypted_plain = codecs.decode(decrypted_hex, "hex").decode()

        print(f"decrypted_binary: {decrypted_binary}")
        print(f"decrypted_hex: {decrypted_hex}")
        print(f"decrypted_plain: {decrypted_plain}")
