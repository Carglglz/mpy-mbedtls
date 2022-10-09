import x509


pk = b'-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIPo9DNo2NqcYZJj2tNCpjTVQR7qgD6ZqhM2aW1BMZ67MoAoGCCqGSM49\nAwEHoUQDQgAEzSMj7qcPqT/tQXw40/PvNBNGptML1eSwdStjvgqdANF9iat25xv9\nbW2DDQLwY70EgiiSwOkkKj8T2/bt2fq11A==\n-----END EC PRIVATE KEY-----\n'

subject = "SN=device.local,O=MicroPython,CN=device"

CSR = x509.gen_csr(subject, pk)

assert isinstance(CSR, bytes)

print("CSR: OK")

