import secrets
import time
import traceback
from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from result import Result, Err, Ok

from contract.register import LocationTokenRegister
from proof.hashes import hash_challenge_input_data, hash_challenge, hash_pub_key, hash_signatures, hash_c_signature
from proof.keys import KeysHolder, from_hex
from proof.proof import ProofOfLocation


@dataclass
class ChallengeInput:
    traveller_id: str
    nonce_t: str
    request_signature: str


@dataclass
class Challenge:
    # the challenge by design has a steep TTL, hence the traveller needs to verify the challenge locally so checksum
    # is provided
    challenger_checksum: str
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

        # challenger checksum
        challenger_checksum = self.keys_holder.checksum_address

        # Assigning local vars here for visibility
        traveller_id = challenge_input.traveller_id
        challenger_id = self.challenger_id
        created_at = self.now_millis()
        nonce_c = self.generate_nonce()
        ttl = self.ttl

        eth_message = encode_defunct(hash_challenge(traveller_id, challenger_id, nonce_c, created_at, ttl))
        c_signature = Account.sign_message(eth_message, private_key=self.keys_holder.priv_key.to_hex()).signature.hex()

        return Ok(Challenge(challenger_checksum, traveller_id, challenger_id, nonce_c, created_at, ttl, c_signature))

    def handle_solution(self, solution: ChallengeSolution) -> Result[ProofOfLocation, str]:
        result = self.verify_solution(solution)
        if result.is_err():
            return Err(result.unwrap_err())

        eth_message = encode_defunct(hash_signatures(solution.c_signature, solution.t_signature))
        proof = Account.sign_message(eth_message, private_key=self.keys_holder.priv_key.to_hex()).signature.hex()

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
            c_signature_data = encode_defunct(hash_challenge(solution.traveller_id,
                                                             solution.challenger_id,
                                                             solution.nonce_c,
                                                             solution.created_at,
                                                             solution.ttl))
            recovered_challenger = Account.recover_message(c_signature_data,
                                                           signature=from_hex(solution.c_signature))
            if recovered_challenger.lower() != self.keys_holder.checksum_address.lower():
                return Err(
                    f"Challenger verification failed - "
                    f"recovered: {recovered_challenger}, "
                    f"actual: {self.keys_holder.checksum_address} ")

            print(f"[✓] Verified c_signature: {solution.c_signature}")

            took = arrived_at - solution.created_at
            if took > solution.ttl:
                print(f"[X] Solution is outdated, took: {took} with ttl of {solution.ttl}")
                return Err(
                    f"Solution is outdated, "
                    f"arrived_at: {arrived_at}, "
                    f"created_at: {solution.created_at}, "
                    f"ttl: {solution.ttl}")

            print(f"[✓] Verified solution is up to date: {solution.c_signature}")

            traveller_pub_key = self.register.get_traveller_pub_key(solution.traveller_id)

            if traveller_pub_key.is_err():
                print("[X] Could not find traveller public key")
                return Err(traveller_pub_key.err())

            traveller_pub_key = traveller_pub_key.unwrap()

            traveller_checksum = keys.PublicKey(from_hex(traveller_pub_key)).to_checksum_address()
            t_signature_data = encode_defunct(hash_c_signature(solution.c_signature))
            recovered_traveller = Account.recover_message(t_signature_data,
                                                          signature=from_hex(solution.t_signature))
            if recovered_traveller != traveller_checksum:
                return Err(
                    f"Could not verify the traveller signature, "
                    f"recovered: {traveller_checksum} actual: {recovered_traveller}")

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
        traveller_checksum = keys.PublicKey(from_hex(traveller_pub_key)).to_checksum_address()
        try:
            challenge_input_data = encode_defunct(
                hash_challenge_input_data(challenge_input.traveller_id, challenge_input.nonce_t))
            recovered_traveller = Account.recover_message(challenge_input_data,
                                                          signature=from_hex(challenge_input.request_signature))
            if recovered_traveller != traveller_checksum:
                return Err(
                    f"Could not verify the request, recovered: {recovered_traveller}, actual: {traveller_checksum}")

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
