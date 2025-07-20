import ipaddress


from result import Ok, Err, Result

from proof.hashes import hash_pub_key


class UnauthorizedAccess(Exception):
    pass

def parse_challenger_request(traveller_pub_key: str, remote_addr: str | None) -> Result[ChallengeInput, str]:
    if __is_local_ip(remote_addr):
        return Err("Not a local address.")
    return Ok(ChallengeInput(hash_pub_key(traveller_pub_key), remote_addr))


def __is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False