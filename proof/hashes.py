from Crypto.Hash import keccak


# keccak is used across the board as it is the only one really available for the EVM
def hash_pub_key(pub_key: str) -> str:
    sha = keccak.new(digest_bits=256)
    sha.update(pub_key.encode())
    return sha.hexdigest()


def hash_c_signature(c_signature: str) -> bytes:
    sha = keccak.new(digest_bits=256)
    sha.update(c_signature.encode())
    return sha.digest()


def hash_signatures(c_signature: str, t_signature: str) -> bytes:
    sha = keccak.new(digest_bits=256)
    sha.update(c_signature.encode())
    sha.update(t_signature.encode())
    return sha.digest()


def hash_challenge_input_data(traveller_id: str, nonce_t: str) -> bytes:
    sha = keccak.new(digest_bits=256)
    sha.update(traveller_id.encode())
    sha.update(nonce_t.encode())
    return sha.digest()


def hash_challenge(traveller_id: str, challenger_id: str, nonce_c: str, created_at: int, ttl: int) -> bytes:
    sha = keccak.new(digest_bits=256)
    sha.update(traveller_id.encode())
    sha.update(challenger_id.encode())
    sha.update(nonce_c.encode())
    sha.update(created_at.to_bytes(32, 'big', signed=False))
    sha.update(ttl.to_bytes(32, 'big', signed=False))
    return sha.digest()
