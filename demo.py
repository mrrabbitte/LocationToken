import time

from dotenv import dotenv_values
from web3.auto import w3

from client.challenge import TravellerKeys, request_challenge, solve, send_solution
from contract.register import LocationTokenRegister

conf = dotenv_values()
dao_address = conf["DAO_ADDRESS"]
register = LocationTokenRegister(dao_address,
                                 "/home/mrrabbit/Code/python/LocationToken/contract/LocationToken.abi.json",
                                 conf["NODE_ADDRESS"])
keys = TravellerKeys(conf['TRAVELLER_PUB_KEY'], conf['TRAVELLER_PRIV_KEY'])

if __name__ == "__main__":
    traveller_address = conf['TRAVELLER_ADDRESS']

    print("Requesting challenge... ")
    challenge = request_challenge(keys)
    print(f"[✓] Got challenge: {challenge}")

    print("Solving...")
    now = time.time()
    solution = solve(keys, challenge)
    took = round((time.time() - now) * 1000)
    print(f"[✓] Solved, took ms: {took}")

    proof = send_solution(solution)

    print(f"[✓] Got proof of location: {proof}")

    print("Registering PoL...")

    tx = {"from": traveller_address, "to": dao_address, "value": w3.to_wei(0.0001, 'ether'), }
    register.register_proof_of_location(proof, tx)

    print("[✓] Registered PoL.")
