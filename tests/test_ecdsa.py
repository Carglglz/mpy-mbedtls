import ecdsa

keyp = ecdsa.ECKeyp()

assert isinstance(keyp, ecdsa.ECKeyp)
assert isinstance(keyp.pkey, bytes)
assert isinstance(keyp.pubkey, bytes)


print("EC key pair: OK")

msg = "hello world"

# Sign
signature = keyp.sign(msg)

assert isinstance(signature, bytes)
print("Signature: OK")

# Verify signature

verification = keyp.verify(msg, signature)

assert verification
print("Verification: OK")

# Load private key

privkey = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICOVN5dKTQWKB0VqBsgN1qTQ4fcPpw4T96Z6mJs2G0+zoAoGCCqGSM49
AwEHoUQDQgAEwv4Aja10MCPDfvNPqo55Ci/bgpGYiGogproKUXXtkwnfY5aCPpdr
o5spOgpWBhhThqTC0R70B8MO8gemlNhNyA==
-----END EC PRIVATE KEY-----"""

n_keyp = ecdsa.ECKeyp(pkey=privkey)

print("Load Private Key: OK")

# Derive public key

n_keyp.derive_pubkey()

assert isinstance(n_keyp.pubkey, bytes)

print("Derive Public Key: OK")





