import os
import mbedtls
from binascii import hexlify
import sys

ciphers = mbedtls.aes_ciphers()
key = os.urandom(16)  # 128 bits key
iv = os.urandom(13)  # Nonce 13 bytes
data = b"foo bar"
add = b"bob alice"

for cipher in ciphers:
    print(cipher, ": ", end="")
    kl = int(cipher.split("-")[1])
    key = os.urandom(int(kl / 8))
    if cipher.endswith("CTR"):
        iv = os.urandom(16)
    else:
        iv = os.urandom(13)
    try:
        ciphertext = mbedtls.aes_encrypt(cipher, key, iv, data, 16, add)

        dec = mbedtls.aes_decrypt(cipher, key, iv, ciphertext, 16, add)

        assert data == dec
        print("OK")
    except Exception as e:
        print(e)
        # sys.print_exception(e)
