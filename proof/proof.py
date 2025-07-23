from dataclasses import dataclass


@dataclass
class ProofOfLocation:
    traveller_id: str
    challenger_id: str
    nonce_c: str
    created_at: int
    ttl: int
    c_signature: str
    t_signature: str
    proof: str
