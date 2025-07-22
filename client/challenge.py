import secrets
from dataclasses import asdict

import requests
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys

from proof.challenger import Challenge, ChallengeInput, ChallengeSolution
from proof.hashes import hash_pub_key, hash_challenge_input_data, hash_c_signature
from proof.keys import from_hex
from proof.proof import ProofOfLocation


class TravellerKeys:

    def __init__(self, pub_key: str, priv_key: str):
        self.traveller_id = hash_pub_key(pub_key)
        self.pub_key = keys.PublicKey(from_hex(pub_key))
        self.priv_key = keys.PrivateKey(from_hex(priv_key))


def request_challenge(traveller_keys: TravellerKeys) -> Challenge:
    nonce_t = __generate_nonce()
    request_signature = Account.sign_message(
        encode_defunct(
            hash_challenge_input_data(
                traveller_keys.traveller_id, nonce_t)), private_key=traveller_keys.priv_key.to_hex()).signature.hex()

    challenge_input = ChallengeInput(traveller_keys.traveller_id, nonce_t, request_signature)
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


def solve(traveller_keys: TravellerKeys, challenge: Challenge) -> ChallengeSolution:
    t_signature = Account.sign_message(
        encode_defunct(
            hash_c_signature(challenge.c_signature)), private_key=traveller_keys.priv_key.to_hex()).signature.hex()
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
