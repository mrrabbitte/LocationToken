import web3.contract
from solcx import compile_standard
from web3 import Web3
from web3.contract import Contract


def read_contract(address: str) -> Contract:
    pass


def deploy_contract() -> web3.contract.Contract:
    with open('LocationToken.sol') as f:
        contract_code = f.read()
        return do_deploy_contract("LocationToken", contract_code)


def do_deploy_contract(contract_name,
                       contract_code,
                       address="http://127.0.0.1:8545",
                       constructor_args=None,
                       owner=None) -> web3.contract.Contract:
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

    return w3.eth.contract(address=tx_receipt.contractAddress, abi=contract_abi)


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


if __name__ == "__main__":
    deploy_contract()
