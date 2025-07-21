import secrets
import time
import traceback
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from result import Result, Err, Ok

from contract.register import LocationTokenRegister
from proof.hashes import hash_challenge_input_data, hash_challenge, hash_pub_key, hash_c_signature, hash_signatures
from proof.keys import KeysHolder


@dataclass
class ChallengeInput:
    traveller_id: str
    nonce_t: str
    request_signature: str


@dataclass
class Challenge:
    # the challenge by design has a steep TTL, hence the traveller needs to verify the challenge locally so pub_key
    # is provided
    challenger_pub_key: str
    traveller_id: str
    challenger_id: str
    nonce_c: str  # 256 random bytes from secure source
    created_at: int  # timestamp in millis
    ttl: int  # time to live in millis
    c_signature: str  # sign_c(hash(traveller_id, challenger_id, nonce, createdAt, ttl)


@dataclass
class ChallengeSolution:
    traveller_id: str
    challenger_id: str
    nonce_c: str
    created_at: int
    ttl: int
    c_signature: str
    # t_signature = sign_t(hash(c_signature)) - this is the solution proving that the private key is in
    # custody of the traveller
    t_signature: str


@dataclass
class ProofOfLocation:
    traveller_id: str
    challenger_id: str
    nonce_c: str
    created_at: int
    ttl: int
    c_signature: str
    t_signature: str
    proof: str


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
        created_at = self.now_millis()
        nonce_c = self.generate_nonce()
        ttl = self.ttl

        c_signature = self.keys_holder.priv_key.sign(
            bytes.fromhex(hash_challenge(traveller_id, challenger_id, nonce_c, created_at, ttl)),
            ec.ECDSA(hashes.SHA512())).hex()

        return Ok(Challenge(challenger_pub_key, traveller_id, challenger_id, nonce_c, created_at, ttl, c_signature))

    def handle_solution(self, solution: ChallengeSolution) -> Result[ProofOfLocation, str]:
        result = self.verify_solution(solution)
        if result.is_err():
            return Err(result.unwrap_err())

        proof = self.keys_holder.priv_key.sign(
            bytes.fromhex(hash_signatures(solution.c_signature, solution.t_signature)),
            ec.ECDSA(hashes.SHA512())).hex()

        return Ok(ProofOfLocation(
            solution.traveller_id,
            solution.challenger_id,
            solution.nonce_c,
            solution.created_at,
            solution.ttl,
            solution.c_signature,
            solution.t_signature,
            proof
        ))

    def verify_solution(self, solution: ChallengeSolution) -> Result[None, str]:
        print(f"Verifying solution: {solution} ...")
        arrived_at = self.now_millis()

        try:
            self.keys_holder.pub_key.verify(
                bytes.fromhex(solution.c_signature),
                bytes.fromhex(hash_challenge(solution.traveller_id,
                                             solution.challenger_id,
                                             solution.nonce_c,
                                             solution.created_at,
                                             solution.ttl)),
                ec.ECDSA(hashes.SHA512()))

            print(f"[✓] Verified c_signature: {solution.c_signature}")

            took = arrived_at - solution.created_at
            if took > solution.ttl:
                print(f"[X] Solution is outdated, took: {took} with ttl of {solution.ttl}")

            print(f"[✓] Verified solution is up to date: {solution.c_signature}")

            traveller_pub_key = self.register.get_traveller_pub_key(solution.traveller_id)

            if traveller_pub_key.is_err():
                print("[X] Could not find traveller public key")
                return Err(traveller_pub_key.err())

            traveller_pub_key = traveller_pub_key.unwrap()

            serialization.load_pem_public_key(traveller_pub_key.encode()).verify(
                bytes.fromhex(solution.t_signature),
                bytes.fromhex(hash_c_signature(solution.c_signature)),
                ec.ECDSA(hashes.SHA512()))
            print(f"[✓] Verified t_signature: {solution.t_signature}")

            return Ok(None)
        except Exception as e:
            traceback.print_exc()
            print(f"Could not verify the challenge solution: {solution}")
            return Err(f"Got exception: {e}")

    def verify_input(self, challenge_input: ChallengeInput) -> Result[None, str]:
        print(f"Verifying input: {challenge_input} ...")
        traveller_pub_key = self.register.get_traveller_pub_key(challenge_input.traveller_id)

        print(f"Got pub key: {traveller_pub_key} ...")

        if traveller_pub_key.is_err():
            return Err(traveller_pub_key.err())

        traveller_pub_key = traveller_pub_key.unwrap()
        try:
            serialization.load_pem_public_key(
                traveller_pub_key.encode()).verify(
                bytes.fromhex(challenge_input.request_signature),
                bytes.fromhex(hash_challenge_input_data(challenge_input.traveller_id, challenge_input.nonce_t)),
                ec.ECDSA(hashes.SHA512()))
            print(f"[✓] Verified signature: {challenge_input}")
            return Ok(None)
        except Exception as e:
            traceback.print_exc()
            print(f"Could not verify the challenge input: {challenge_input}")
            return Err(f"Got exception: {e}")

    def now_millis(self) -> int:
        return int(round(time.time() * 1000))

    def generate_nonce(self) -> str:
        return secrets.token_bytes(self.nonce_length).hex()
