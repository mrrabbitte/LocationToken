from result import Result, Ok


class LocationTokenRegister:

    def get_traveller_pub_key(self, traveller_id: str) -> Result[str, str]:
        return Ok("""-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEjqDSta52o6bg9G9fooNJ7EAdmI16hJdd
Su29O/ocBD8iYGFZwnpIBc1yJA19O6eyNp/BzyYhsRvDLceW8HMW3g==
-----END PUBLIC KEY-----""")
