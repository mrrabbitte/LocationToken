import time

from dotenv import dotenv_values

from client.challenge import TravellerKeys, request_challenge, solve, send_solution

if __name__ == "__main__":
    conf = dotenv_values()
    keys = TravellerKeys(conf['TRAVELLER_PUB_KEY'], conf['TRAVELLER_PRIV_KEY'])

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
