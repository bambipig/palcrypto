from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


sha512_hash_algorithm = hashes.SHA512()
rsa_padding = padding.OAEP(
    mgf=padding.MGF1(algorithm=sha512_hash_algorithm),
    algorithm=sha512_hash_algorithm,
    label=None,
)


def generate_key() -> str:
    key = Fernet.generate_key()
    return key.decode()


def generate_rsa_key_pair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return {
        'private_key': private_key,
        'public_key': public_key,
    }


def fernet_encrypt(key: str, raw_data: bytes) -> bytes:
    f = Fernet(key.encode())

    return f.encrypt(raw_data)


def fernet_decrypt(key: str, encrypted_data: bytes) -> bytes:
    f = Fernet(key.encode())

    return f.decrypt(encrypted_data)


def load_pem_private_key(private_key: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(private_key.encode())


def load_pem_public_key(public_key: str) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(public_key.encode())


def rsa_sign(private_key_obj: rsa.RSAPrivateKey, data: bytes):
    return private_key_obj.sign(
        data,
        padding=rsa_padding,
        algorithm=sha512_hash_algorithm)


def rsa_sign_verify(public_key_obj: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    public_key_obj.verify(
        signature=signature,
        data=data,
        padding=rsa_padding,
        algorithm=sha512_hash_algorithm
    )


def rsa_encrypt(public_key_obj: rsa.RSAPublicKey, raw_data: bytes) -> bytes:
    return public_key_obj.encrypt(
        plaintext=raw_data,
        padding=rsa_padding
    )


def rsa_decrypt(private_key_obj: rsa.RSAPrivateKey, encrypted_data: bytes):
    return private_key_obj.decrypt(
        ciphertext=encrypted_data,
        padding=rsa_padding,
    )
