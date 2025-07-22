import json

from cryptography.hazmat.primitives import serialization
from result import Result, Ok
from web3 import Web3

from proof.proof import ProofOfLocation


class LocationTokenRegister:

    def __init__(self, dao_address: str, abi_path: str, node_addr: str):
        w3 = Web3(Web3.HTTPProvider(node_addr))
        w3.eth.defaultAccount = w3.eth.accounts
        with open(abi_path) as f:
            abi = json.load(f)
        self.contract = w3.eth.contract(address=dao_address, abi=abi)

    def get_traveller_pub_key(self, traveller_id: str) -> Result[str, str]:
        response = self.contract.functions.getTravellerPubKey(travellerId=traveller_id).call()
        pub_key = serialization.load_pem_public_key(response).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return Ok(pub_key)

    def get_challenger_pub_key(self, challenger_id: str):
        response = self.contract.functions.getChallengerPubKey(challengerId=challenger_id).call()
        pub_key = serialization.load_pem_public_key(response).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return Ok(pub_key)

    def register_proof_of_location(self, proof: ProofOfLocation, tx: dict):
        response = self.contract.functions.registerLocationProof(
            travellerId=proof.traveller_id,
            challengerId=proof.challenger_id,
            nonce_c=proof.nonce_c,
            created_at=proof.created_at,
            ttl=proof.ttl,
            c_signature=bytes.fromhex(proof.c_signature),
            t_signature=bytes.fromhex(proof.t_signature),
            proof=bytes.fromhex(proof.proof)
        ).transact(tx)
        print(response)
