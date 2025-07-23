# import base64
# import json
# import secrets
# import time
# from dataclasses import dataclass
# from hashlib import sha512
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.exceptions import InvalidSignature
#
#
# @dataclass
# class ChallengeBody:
#     traveller_pub_key: str
#     challenger_pub_key: str
#     challenge: str
#     created_at: int
#     ttl_millis: int
#
# @dataclass
# class Challenge:
#     body: ChallengeBody
#     challenge_signature: str
#
# @dataclass
# class TravellerResponse:
#     traveller_pub_key: str
#     challenge: Challenge
#     signature: str
#
# @dataclass
# class ProofOfLocation:
#     created_at: int
#     traveller_pub_key: str
#     challenge: str
#     challenge_signature: str
#     traveller_response: str
#     challenger_attestation: str
#
# PRIVATE_KEY_PEM = b""  # PEM private key
# PUBLIC_KEY_PEM = b""   # PEM public key
#
# def encode(data: bytes) -> str:
#     return base64.urlsafe_b64encode(data).decode()
#
# def digest_challenge(challenge: ChallengeBody) -> bytes:
#     sha = sha512()
#     sha.update(challenge.created_at.to_bytes(16, 'little'))
#     sha.update(challenge.ttl_millis.to_bytes(8, 'little'))
#     sha.update(challenge.traveller_pub_key.encode())
#     sha.update(challenge.challenger_pub_key.encode())
#     sha.update(challenge.challenge.encode())
#     return sha.digest()
#
# def sign_challenge(challenge_body: ChallengeBody) -> Challenge:
#     private_key = serialization.load_pem_private_key(PRIVATE_KEY_PEM, password=None)
#     signature = private_key.sign(digest_challenge(challenge_body), ec.ECDSA(hashes.SHA512()))
#     signature_b64 = encode(signature)
#     return Challenge(body=challenge_body, challenge_signature=signature_b64)
#
# def create_challenge(traveller_id: str) -> Challenge:
#     rand_bytes = secrets.token_bytes(64)
#     challenge = encode(rand_bytes)
#     now = int(time.time() * 1000)
#     challenge_body = ChallengeBody(
#         traveller_pub_key=traveller_id,
#         challenger_pub_key=PUBLIC_KEY_PEM.decode(),
#         challenge=challenge,
#         created_at=now,
#         ttl_millis=100
#     )
#     return sign_challenge(challenge_body)
#
# def issue_location_proof(response: TravellerResponse) -> ProofOfLocation:
#     traveller_public_key = serialization.load_pem_public_key(response.traveller_pub_key.encode())
#     signature = base64.urlsafe_b64decode(response.signature)
#     challenge_digest = digest_challenge(response.challenge.body)
#
#     # verify traveller signature
#     traveller_public_key.verify(signature, challenge_digest, ec.ECDSA(hashes.SHA512()))
#
#     return ProofOfLocation(
#         created_at=response.challenge.body.created_at,
#         traveller_pub_key=response.traveller_pub_key,
#         challenge=response.challenge.body.challenge,
#         challenge_signature=response.challenge.challenge_signature,
#         traveller_response=response.signature,
#         challenger_attestation="TODO: Generate attestation signature"
#     )
