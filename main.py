from flask import Flask
from flask import request

from proof.input import parse_challenger_request

app = Flask(__name__)

@app.route("/")
def hello_world():
    parse_challenger_request("", request.remote_addr)
    return "<p>Hello, World!</p>"

if __name__ == "__main__":
    app.run()