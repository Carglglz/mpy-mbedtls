from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
# Generate our key
key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.SURNAME, "Foo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MicroPython"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Bar"),
        ]
    )

cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

print("CA CERT:")
print(cert.public_bytes(serialization.Encoding.PEM).decode())


user_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
user_subject  = x509.Name(
            [
                x509.NameAttribute(NameOID.SURNAME, "UserFoo"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MicroPython"),
                x509.NameAttribute(NameOID.COMMON_NAME, "UserBar"),
            ]
        )

csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(user_subject)
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.DNSName("wss://192.168.1.1:8833"),
                            x509.DNSName("wss://192.168.4.1:8833"),
                        ]
                    ),
                    critical=False,
                )
                .sign(user_key, hashes.SHA256(), default_backend())
            )


user_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(issuer)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=1825))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("wss://192.168.1.1:8833"),
                        x509.DNSName("wss://192.168.4.1:8833"),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )


print("USER CERT:")
print(user_cert.public_bytes(serialization.Encoding.PEM).decode())
