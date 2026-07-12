from unittest import TestCase

from webauthn.helpers.exceptions import InvalidCBORData
from webauthn.helpers.parse_cbor import parse_cbor


class TestParseCBOR(TestCase):
    def test_should_reject_duplicate_keys_in_cbor(self) -> None:
        # Data: {1: 2, true: 3} (`true` == Python `True` == `1`, which overwrites original `1`)
        malicious_cbor = bytes.fromhex("a20102f503")

        with self.assertRaises(InvalidCBORData) as exc:
            parse_cbor(malicious_cbor)

        self.assertRegex(str(exc.exception.__cause__), "Duplicate map key")
