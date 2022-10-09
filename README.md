### mpy-mbedtls

MicroPython bindings for ECDSA keys basic functionality and x509 cert/csr utilities.
*Supports both PEM and DER formats*

#### Features:

`mbedtls` module (low level):

   - Generate ECDSA key pair
	
   - Derive public key from private key
	
   - Sign data
    
   - Verify signature

`x509` module:
	
   - Generate a certificate signing request (CSR)
	
   - Parse certificate
	
   - Verify certificate
   
`ecdsa` module (Same as mbedtls but OOP):
   
   - Generate ECDSA key pair
	
   - Derive public key from private key
   
   - Parse private/public key file
	
   - Sign data
    
   - Verify signature
   
   - Sign file 
   
   - Verify file signature
   
   - Export private/public key to file



#### Install

`esp32` port:

In `micropython/ports/esp32`

```console
$ make BOARD=GENERIC USER_C_MODULES=../../../../<path to user modules>/mpy-mbedtls/micropython.cmake FROZEN_MANIFEST=<absolute path to user modules>/mpy-mbedtls/ports/esp32/manifest.py -j4
```

Other ports (e.g. `unix`):

Needs enabling additional options for mbedtls, see `mpy-mbedtls/mbedtls/mbedtls_config.h`

In `micropython/ports/unix`

```
$ make USER_C_MODULES=../../../<path to user modules>/mpy-mbedtls FROZEN_MANIFEST=../../../<path to user modules>/mpy-mbedtls/ports/unix/manifest.py -j4
```

#### Run tests

In `micropython/tests`

```
$ ./run-tests.py ../../<path to user modules>/mpy-mbedtls/tests/test_*.py
pass  ../../user_modules/mpy-mbedtls/tests/test_mbedtls_ec_curves.py
pass  ../../user_modules/mpy-mbedtls/tests/test_mbedtls_ec_keyp_der.py
pass  ../../user_modules/mpy-mbedtls/tests/test_mbedtls_ec_keyp.py
pass  ../../user_modules/mpy-mbedtls/tests/test_x509_cert_parse.py
pass  ../../user_modules/mpy-mbedtls/tests/test_ecdsa.py
pass  ../../user_modules/mpy-mbedtls/tests/test_x509_gen_csr.py
pass  ../../user_modules/mpy-mbedtls/tests/test_x509_cert_validate.py
7 tests performed (19 individual testcases)
7 tests passed

```

#### Example 

```python
import ecdsa

keyp = ecdsa.ECKeyp()

print("PRIVATE KEY:")
print(keyp.pkey.decode())

print("PUBLIC KEY:")
print(keyp.pubkey.decode())

msg = "hello world"

# Sign
signature = keyp.sign(msg)

assert isinstance(signature, bytes)
print("Signature: OK")

# Verify signature

verification = keyp.verify(msg, signature)

assert verification
print("Verification: OK")


```

```
>>> import example
PRIVATE KEY:
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGrK/lMb3BvPEk2LhBmRWj01duluiI/qagOFQaXfGIOAoAoGCCqGSM49
AwEHoUQDQgAEzKw4gnXWWVfNy2dP6WYzJ4UN/E5DPhyJdUEtYC4j8PvXTnFPdpga
XXN+n0oofGF/aTfwX3UqNkc+qvUKtkPzKg==
-----END EC PRIVATE KEY-----

PUBLIC KEY:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzKw4gnXWWVfNy2dP6WYzJ4UN/E5D
PhyJdUEtYC4j8PvXTnFPdpgaXXN+n0oofGF/aTfwX3UqNkc+qvUKtkPzKg==
-----END PUBLIC KEY-----

Signature: OK
Verification: OK
```


See other examples in `mpy-mbedtls/tests`