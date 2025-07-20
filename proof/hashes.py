from hashlib import sha512

from proof.challenger import ChallengeInput


def hash_pub_key(pub_key: str) -> str:
    sha = sha512()
    sha.update(pub_key.encode())
    return sha.digest().decode()

def hash_challenge_input(challenge_input: ChallengeInput) -> str:
    sha = sha512()
    sha.update(challenge_input.traveller_id.encode())
    sha.update(challenge_input.nonce_t.encode())
    return sha.digest().decode()

def hash_challenge(traveller_id: str, challenger_id: str, nonce_c: str, created_at: int, ttl: int) -> str:
    sha = sha512()
    sha.update(traveller_id.encode())
    sha.update(challenger_id.encode())
    sha.update(nonce_c.encode())
    sha.update(created_at.to_bytes(16, 'big', signed=False))
    sha.update(ttl.to_bytes(16, 'big', signed=False))
    return sha.digest().decode()