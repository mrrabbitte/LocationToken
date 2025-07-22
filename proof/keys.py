import secrets
from typing import Tuple

from eth_keys import keys


class KeysHolder:

    def __init__(self, pub_key: str, priv_key: str):
        self.pub_key_raw = pub_key
        self.pub_key = keys.PublicKey(from_hex(pub_key))
        self.priv_key = keys.PrivateKey(from_hex(priv_key))
        self.checksum_address = self.pub_key.to_checksum_address()


def from_hex(b: str) -> bytes:
    return bytes.fromhex(b.replace("0x", ""))


def __generate_keys() -> Tuple[str, str, str]:
    private_key_bytes = secrets.token_bytes(32)
    private_key = keys.PrivateKey(private_key_bytes)
    public_key = private_key.public_key
    address = public_key.to_checksum_address()

    return private_key.to_hex(), public_key.to_hex(), address


if __name__ == "__main__":
    priv, pub, checksum = __generate_keys()
    print(priv)
    print(pub)
    print(checksum)

    assert keys.PrivateKey(from_hex(priv.replace("0x", ""))).to_hex() == priv
