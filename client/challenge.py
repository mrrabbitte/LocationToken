import secrets
from dataclasses import asdict

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from proof.challenger import Challenge, ChallengeInput, ChallengeSolution
from proof.hashes import hash_pub_key, hash_challenge_input_data, hash_c_signature
from proof.proof import ProofOfLocation


class TravellerKeys:

    def __init__(self, pub_key: str, priv_key: str):
        self.pub_key = serialization.load_pem_public_key(pub_key.encode())
        self.priv_key = serialization.load_pem_private_key(priv_key.encode(), password=None)
        self.traveller_id = hash_pub_key(pub_key)


def request_challenge(keys: TravellerKeys) -> Challenge:
    nonce_t = __generate_nonce()
    challenge_input = ChallengeInput(keys.traveller_id, nonce_t,
                                     keys.priv_key.sign(
                                         bytes.fromhex(hash_challenge_input_data(keys.traveller_id, nonce_t)),
                                         ec.ECDSA(hashes.SHA512()))
                                     .hex())
    response = requests.post("http://127.0.0.1:5000/v1/challenge", json=asdict(challenge_input))
    print(f"Got response: {response.status_code}, {response.content}")
    if not response.ok:
        raise Exception(response.content)
    data = response.json()
    return Challenge(**data)


def send_solution(solution: ChallengeSolution) -> ProofOfLocation:
    response = requests.post("http://127.0.0.1:5000/v1/solution", json=asdict(solution))
    print(f"Got response: {response.status_code}, {response.content}")
    if not response.ok:
        raise Exception(response.content)
    data = response.json()
    return ProofOfLocation(**data)


def solve(keys: TravellerKeys, challenge: Challenge) -> ChallengeSolution:
    t_signature = keys.priv_key.sign(
        bytes.fromhex(hash_c_signature(challenge.c_signature)),
        ec.ECDSA(hashes.SHA512())).hex()
    return ChallengeSolution(
        challenge.traveller_id,
        challenge.challenger_id,
        challenge.nonce_c,
        challenge.created_at,
        challenge.ttl,
        challenge.c_signature,
        t_signature)


def __generate_nonce() -> str:
    return secrets.token_bytes(128).hex()
