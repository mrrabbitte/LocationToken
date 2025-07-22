import json

import web3.contract
from cryptography.hazmat.primitives import serialization
from solcx import compile_standard
from web3 import Web3
from web3.auto import w3
from web3.contract import Contract

from contract.register import LocationTokenRegister
from proof.hashes import hash_pub_key


def read_contract(address: str) -> Contract:
    pass


def deploy_contract(owner: str) -> (web3.contract.Contract, dict):
    with open('LocationToken.sol') as f:
        contract_code = f.read()
        return do_deploy_contract("LocationToken", contract_code, owner=owner)


def do_deploy_contract(contract_name,
                       contract_code,
                       address="http://127.0.0.1:8545",
                       constructor_args=None,
                       owner=None) -> (web3.contract.Contract, dict):
    print(f"Deploying: {contract_name}")
    w3 = Web3(Web3.HTTPProvider(address))  # requires hardhat node running
    if owner:
        w3.eth.defaultAccount = owner
    else:
        w3.eth.defaultAccount = w3.eth.accounts
    compiled = compile_contract(contract_name, contract_code)
    contract_interface = compiled["contracts"][contract_name]
    contract_interface = list(contract_interface.values())[0]
    contract_abi = contract_interface["abi"]
    eth_contract = w3.eth.contract(abi=contract_abi,
                                   bytecode=contract_interface["evm"]["bytecode"]["object"])
    tx = None
    if owner:
        tx = {'from': owner}
    if constructor_args is None:
        tx_hash = eth_contract.constructor().transact(tx)
    else:
        tx_hash = eth_contract.constructor(**constructor_args).transact(tx)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    return (w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_abi), contract_abi)


def compile_contract(contract_name: str, contract_code: str) -> dict:
    return compile_standard({
        "language": "Solidity",
        "sources": {
            contract_name: {
                "content": contract_code
            }
        },
        "settings": {
            "optimizer": {
                "enabled": True,
                "runs": 200
            },
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            },
            "viaIR": True
        }
    })


def to_pub_key_bytes(pub_key: str) -> bytes:
    return serialization.load_pem_public_key(
        pub_key.encode()).public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)


if __name__ == "__main__":
    # This is for testing purposes: it deploys the contract, registers a challenger and a traveller.
    # - challenger address: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
    # - traveller address: 0x90F79bf6EB2c4f870365E785982E1f101E93b906
    # - contract owner: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

    challenger_pub_key_pem = """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEx1sbmtfABYamaqTqb0bosTbeyZcSF9cF
QZHyktbPsJvEaCpUW4c3uLG1a/Aft2AOudw+b/rX0ufsMsaRbNfB2g==
-----END PUBLIC KEY-----"""
    traveller_pub_key_pem = """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEjqDSta52o6bg9G9fooNJ7EAdmI16hJdd
Su29O/ocBD8iYGFZwnpIBc1yJA19O6eyNp/BzyYhsRvDLceW8HMW3g==
-----END PUBLIC KEY-----"""
    challenger_addr = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    traveller_addr = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"

    deploy_response = deploy_contract("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
    contract = deploy_response[0]
    print(f"[✓] Deployed contract at address: {contract.address}")

    print("Registering challenger...")
    tx = {"from": challenger_addr, "to": contract.address, "value": w3.to_wei(0.0001, 'ether'), }
    challenger_pub_key = to_pub_key_bytes(challenger_pub_key_pem)
    challenger_id = hash_pub_key(challenger_pub_key_pem)
    wifi_network = "DublinCastleLocationWifi"

    scale_lat = 100
    lat = 533440956
    scale_lon = 10
    lon = 62674862

    contract.functions.registerChallenger(challengerPubKey=challenger_pub_key,
                                          challengerId=challenger_id,
                                          wifiNetwork=wifi_network,
                                          scaleLat=scale_lat,
                                          lat=lat,
                                          scaleLon=scale_lon,
                                          lon=lon).transact(tx)
    print(f"[✓] Registered challenger: {challenger_id}")

    print("Registering traveller...")
    tx = {"from": traveller_addr, "to": contract.address, "value": w3.to_wei(0.0001, 'ether'), }
    traveller_pub_key = to_pub_key_bytes(traveller_pub_key_pem)
    traveller_id = hash_pub_key(traveller_pub_key_pem)
    contract.functions.registerTraveller(travellerId=traveller_id,
                                         travellerPubKey=traveller_pub_key).transact(tx)

    print(traveller_pub_key)
    print(f"[✓] Registered traveller: {traveller_id}")

    abi = deploy_response[1]

    with open('LocationToken.abi.json', 'w') as f:
        json.dump(abi, f)
    print("[✓] Saved contract ABI.")

    print("Performing checks...")
    register = LocationTokenRegister(contract.address, "LocationToken.abi.json")

    read_traveller_pub_key_pem = register.get_traveller_pub_key(traveller_id).unwrap()
    assert (read_traveller_pub_key_pem.replace("\n", "")
            == traveller_pub_key_pem.replace("\n", ""))

    read_challenger_pub_key_pem = register.get_challenger_pub_key(challenger_id).unwrap()
    assert (read_challenger_pub_key_pem.replace("\n", "")
            == challenger_pub_key_pem.replace("\n", ""))

    print(f"[✓] Checks OK. Contract ready: {contract.address}")
