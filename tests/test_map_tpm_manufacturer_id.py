from unittest import TestCase

from webauthn.helpers.tpm import map_tpm_manufacturer_id


class TestWebAuthnGenerateUserHandle(TestCase):
    def test_handles_recognized_id(self) -> None:
        info = map_tpm_manufacturer_id("id:4353434F")

        self.assertEqual(info.name, "Cisco")
        self.assertEqual(info.id, "CSCO")

    def test_raises_on_unrecognized_id(self) -> None:
        with self.assertRaises(KeyError):
            map_tpm_manufacturer_id("id:FFFFFFFF")

    def test_normalizes_id_before_lookup_qualcomm(self) -> None:
        # A real TPM manufacturer ID observed in the wild. The final "d" should be a "D"
        info = map_tpm_manufacturer_id("id:51434f4d")

        self.assertEqual(info.name, "Qualcomm")
        self.assertEqual(info.id, "QCOM")

    def test_normalizes_id_before_lookup_ibm(self) -> None:
        info = map_tpm_manufacturer_id("id:49424d00")

        self.assertEqual(info.name, "IBM")
        self.assertEqual(info.id, "IBM")
