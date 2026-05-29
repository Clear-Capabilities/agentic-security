from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519

# ECDH key agreement guarding customer PII — HNDL-critical.
def generate_session_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def encrypt_customer_secret(plaintext: bytes, public_key) -> bytes:
    # RSA-OAEP encrypting a credential — long-lived ciphertext.
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def generate_x25519():
    return x25519.X25519PrivateKey.generate()
