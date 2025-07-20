import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from result import Result, Err, Ok

from contract.register import LocationTokenRegister
from proof.hashes import hash_challenge_input, hash_challenge, hash_pub_key
from proof.keys import KeysHolder


@dataclass
class ChallengeInput:
    traveller_id: str
    nonce_t: str
    request_signature: str

@dataclass
class Challenge:
    challenger_pub_key: str # the challenge by design has a steep TTL, hence the traveller needs to verify the challenge locally
    traveller_id: str
    challenger_id: str
    nonce_c: str #  256 random bytes from secure source
    created_at: int # timestamp in millis
    ttl: int # time to live in millis
    c_signature: str # sign_c(hash(traveller_id, challenger_id, nonce, createdAt, ttl)

class Challenger:

    def __init__(self, register: LocationTokenRegister, keys_holder: KeysHolder, nonce_length=256, ttl=50):
        self.register = register
        self.keys_holder = keys_holder
        self.challenger_id = hash_pub_key(keys_holder.pub_key_raw)
        self.nonce_length = nonce_length
        self.ttl = ttl

    def request_challenge(self, challenge_input: ChallengeInput) -> Result[Challenge, str]:
        ver_result = self.verify_input(challenge_input)
        if ver_result.is_err():
            return Err(ver_result.unwrap_err())

        # challenger pub key
        challenger_pub_key = self.keys_holder.pub_key_raw

        # Assigning local vars here for visibility
        traveller_id = challenge_input.traveller_id
        challenger_id = self.challenger_id
        created_at = int(round(time.time() * 1000))
        nonce_c = self.generate_nonce()
        ttl = self.ttl

        c_signature = self.keys_holder.priv_key.sign(
            hash_challenge(traveller_id, challenger_id,  nonce_c, created_at, ttl))

        return Ok(Challenge(challenger_pub_key, traveller_id, challenger_id, nonce_c, created_at, ttl, c_signature))


    def verify_input(self, challenge_input: ChallengeInput) -> Result[None, str]:
        traveller_pub_key = self.register.get_traveller_pub_key(challenge_input.traveller_id)
        if traveller_pub_key.is_err():
            return Err(traveller_pub_key.err())

        traveller_pub_key = traveller_pub_key.unwrap()
        try:
            serialization.load_pem_public_key(
                traveller_pub_key.encode()).verify(
                challenge_input.request_signature.encode(),
                hash_challenge_input(challenge_input).encode(),
                ec.ECDSA(hashes.SHA512()))
            return Ok(None)
        except Exception as e:
            return Err(f"Got exception: {e}")

    def generate_nonce(self) -> str:
        return secrets.token_bytes(self.nonce_length).decode()