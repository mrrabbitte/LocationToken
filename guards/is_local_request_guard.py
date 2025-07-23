import ipaddress

from result import Result, Err, Ok


def is_local_request(remote_addr: str) -> Result[None, str]:
    if not __is_local_ip(remote_addr):
        return Err("Not a local address.")
    return Ok(None)


def __is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False
