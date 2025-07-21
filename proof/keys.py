from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KeysHolder:

    def __init__(self, pub_key: str, priv_key: str):
        self.pub_key_raw = pub_key
        self.pub_key = serialization.load_pem_public_key(pub_key.encode())
        self.priv_key = serialization.load_pem_private_key(priv_key.encode(), password=None)


def __generate_keys() -> Tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())


if __name__ == "__main__":
    priv, pub = __generate_keys()
    print(priv)
    print(pub)
