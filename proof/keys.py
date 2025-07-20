from cryptography.hazmat.primitives import serialization


class KeysHolder:

    def __init__(self, pub_key: str, priv_key: str):
        self.pub_key_raw = pub_key
        self.pub_key = serialization.load_pem_public_key(pub_key.encode())
        self.priv_key = serialization.load_pem_private_key(priv_key.encode(), password=None)
