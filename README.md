# LocationToken

This is an implementation of a Proof of Location based on the Ethereum smart contract and simple WiFi confirmation of
the location by a network of trusted Challengers (anchor model). There are other projects which use a different approach and are
available in production, this is only an experiment for study purposes.

# Installing dependencies

All dependencies are specified in the `requirements.txt` file, and can be installed using
`pip install -r requirements.txt`

# Running the Demo Deployment script

You can run the deployment script by running:

`python3 deploy.py`

This will create the contract on the target ETH chain, the contract ABI, and register both the Traveller and the
Challenger. It will also print the contract address which should be used in the `.env` variable `DAO_ADDRESS` before
running both the server and the demo.

# Running the Challenger Server

In order to run the server simply run the `main.py` file like so:
`python3 main.py`

The `.env` file contains all the configuration data. If you are running locally, you can run the deployment script
and paste the contract address to the appropriate env variable.

# Running the Traveller demo

You can run the demo by simply calling:

`python3 demo.py`

The demo uses the same `.env` configuration file as the server for convenience reasons.


