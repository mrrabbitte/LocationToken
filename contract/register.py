from dataclasses import dataclass

from result import Result


class LocationTokenRegister:

    def get_traveller_pub_key(self, traveller_id: str) -> Result[str, str]:
        pass