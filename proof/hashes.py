from hashlib import sha512


def hash_pub_key(pub_key: str) -> str:
    sha = sha512()
    sha.update(pub_key.encode())
    return sha.hexdigest()


def hash_c_signature(c_signature: str) -> str:
    sha = sha512()
    sha.update(c_signature.encode())
    return sha.hexdigest()


def hash_signatures(c_signature: str, t_signature: str) -> str:
    sha = sha512()
    sha.update(c_signature.encode())
    sha.update(t_signature.encode())
    return sha.hexdigest()


def hash_challenge_input_data(traveller_id: str, nonce_t: str) -> str:
    sha = sha512()
    sha.update(traveller_id.encode())
    sha.update(nonce_t.encode())
    return sha.hexdigest()


def hash_challenge(traveller_id: str, challenger_id: str, nonce_c: str, created_at: int, ttl: int) -> str:
    sha = sha512()
    sha.update(traveller_id.encode())
    sha.update(challenger_id.encode())
    sha.update(nonce_c.encode())
    sha.update(created_at.to_bytes(16, 'big', signed=False))
    sha.update(ttl.to_bytes(16, 'big', signed=False))
    return sha.hexdigest()
