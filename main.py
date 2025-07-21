from dataclasses import asdict

from dotenv import load_dotenv, dotenv_values
from flask import Flask, abort, request, jsonify
from result import Result

from contract.register import LocationTokenRegister
from guards.is_local_request_guard import is_local_request
from proof.challenger import Challenger, ChallengeInput, ChallengeSolution
from proof.keys import KeysHolder

# Loading env variables
load_dotenv()

conf = dotenv_values()

# Dependencies
register = LocationTokenRegister()
keys_holder = KeysHolder(conf['CHALLENGER_PUB_KEY'], conf['CHALLENGER_PRIV_KEY'])
challenger = Challenger(register, keys_holder)

# The app
app = Flask(__name__)


@app.route("/v1/challenge", methods=['POST'])
def issue_challenge():
    __handle_guard_error(is_local_request(request.remote_addr))

    challenge_input = ChallengeInput(**request.get_json())

    challenge_response = challenger.request_challenge(challenge_input)

    if challenge_response.is_err():
        abort(400, {'message': challenge_response.unwrap_err()})

    return jsonify(asdict(challenge_response.unwrap()))


@app.route("/v1/solution", methods=['POST'])
def handle_solution():
    __handle_guard_error(is_local_request(request.remote_addr))

    solution = ChallengeSolution(**request.get_json())

    solution_response = challenger.handle_solution(solution)

    if solution_response.is_err():
        abort(400, {"message": solution_response.unwrap_err()})

    return jsonify(asdict(solution_response.unwrap()))


def __handle_guard_error(result: Result[None, str]):
    if result.is_err():
        abort(400, {'message': result.unwrap_err()})


if __name__ == "__main__":
    app.run()
