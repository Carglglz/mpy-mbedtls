# This test won't run under CPython because it requires mbedtls module

try:
    import mbedtls
except ImportError:
    print("SKIP")
    raise SystemExit


# Gen key pair
keyp = mbedtls.ec_gen_key("secp256r1")

assert isinstance(keyp, tuple)

assert len(keyp) == 2

print(f"EC Key Pair: {len(keyp)}, {type(keyp)}")

pk, pubk = keyp

# Derive public key from private key

d_pubk = mbedtls.ec_get_pubkey(pk, mbedtls.FORMAT_PEM)

assert pubk == d_pubk
print("Derive public key: OK")


# Sign a message
msg = b"hello world"
sig = mbedtls.ec_key_sign(pk, msg)

assert isinstance(sig, bytes)
print(f"Signature: {type(sig)}")

# Verify signature
valid = mbedtls.ec_key_verify(pubk, msg, sig)

assert valid

print("Valid signature: ", valid)
