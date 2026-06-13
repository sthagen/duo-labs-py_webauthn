from unittest import TestCase
from unittest.mock import patch
from datetime import datetime
from OpenSSL.crypto import X509, X509Store, X509StoreContextError
from base64 import urlsafe_b64decode

from webauthn.helpers.exceptions import InvalidCertificateChain
from webauthn.helpers.known_root_certs import (
    apple_webauthn_root_ca,
    globalsign_root_ca,
    google_hardware_attestation_root_4,
)
from webauthn.helpers.validate_certificate_chain import (
    validate_certificate_chain,
)

from .helpers.x509store import patch_validate_certificate_chain_x509store_getter

apple_x5c_certs = [
    # 2021-08-31 @ 23:02:07Z <-> 2021-09-03 @ 23:02:07Z
    bytes.fromhex(
        "30820243308201c9a0030201020206017ba3992221300a06082a8648ce3d0403023048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3231303833313233303230375a170d3231303930333233303230375a3081913149304706035504030c4062313066373138626335646437353838383661316438636662356238623633313732396634643765346261303639616230613939326331633038343738616639311a3018060355040b0c114141412043657274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613059301306072a8648ce3d020106082a8648ce3d03010703420004d124b0e9ff8192723c9ee2fa4f8170d373e03286cf880aeec7008a14cdea64724963e05bb8c44a9f980ded12aa8a33795cf81d31e74116ced6f1f4c5eb0c358fa3553053300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f0303306092a864886f76364080204263024a1220420e457e5bc292f1635210248ed2e776ba129c7cc469524a75356836caef2f058a0300a06082a8648ce3d0403020368003065023065c6e7075ddacb50879a8412904759013d0da78726408759a01f1994c1795a69c2c1d11306c2d1bc97be6141627b8677023100ab0b9e7d97ca2b603b1edb6e264c49bf1971380c2afa5d37f8c4ff5a5de6d457a19cb80c02b2edf94b0853e0482f8686"
    ),
    # 2020-03-18 @ 18:38:01Z <-> 2030-03-13 @ 00:00:00Z
    bytes.fromhex(
        "30820234308201baa003020102021056255395c7a7fb40ebe228d8260853b6300a06082a8648ce3d040303304b311f301d06035504030c164170706c6520576562417574686e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333830315a170d3330303331333030303030305a3048311c301a06035504030c134170706c6520576562417574686e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b8104002203620004832e872f261491810225b9f5fcd6bb6378b5f55f3fcb045bc735993475fd549044df9bfe19211765c69a1dda050b38d45083401a434fb24d112d56c3e1cfbfcb9891fec0696081bef96cbc77c88dddaf46a5aee1dd515b5afaab93be9c0b2691a366306430120603551d130101ff040830060101ff020100301f0603551d2304183016801426d764d9c578c25a67d1a7de6b12d01b63f1c6d7301d0603551d0e04160414ebae82c4ffa1ac5b51d4cf24610500be63bd7788300e0603551d0f0101ff040403020106300a06082a8648ce3d0403030368003065023100dd8b1a3481a5fad9dbb4e7657b841e144c27b75b876a4186c2b1475750337227efe554457ef648950c632e5c483e70c102302c8a6044dc201fcfe59bc34d2930c1487851d960ed6a75f1eb4acabe38cd25b897d0c805bef0c7f78b07a571c6e80e07"
    ),
]


class TestValidateCertificateChain(TestCase):
    def setUp(self):
        # Setting the time to something that satisfies all these:
        # (Leaf) 20210831230207Z <-> 20210903230207Z <- Earliest expiration
        # (Int.) 20200318183801Z <-> 20300313000000Z
        # (Root) 20200318182132Z <-> 20450315000000Z
        self.x509store_time = datetime(2021, 9, 1, 0, 0, 0)

    @patch_validate_certificate_chain_x509store_getter
    def test_validates_certificate_chain(self, patched_x509store: X509Store) -> None:
        patched_x509store.set_time(self.x509store_time)

        try:
            validate_certificate_chain(
                x5c=apple_x5c_certs,
                pem_root_certs_bytes=[apple_webauthn_root_ca],
            )
        except Exception as err:
            print(err)
            self.fail("validate_certificate_chain failed when it should have succeeded")

    @patch_validate_certificate_chain_x509store_getter
    def test_throws_on_bad_root_cert(self, patched_x509store: X509Store) -> None:
        patched_x509store.set_time(self.x509store_time)

        with self.assertRaises(InvalidCertificateChain):
            validate_certificate_chain(
                x5c=apple_x5c_certs,
                # An obviously invalid root cert for these x5c certs
                pem_root_certs_bytes=[globalsign_root_ca],
            )

    def test_passes_on_no_root_certs(self):
        try:
            validate_certificate_chain(
                x5c=apple_x5c_certs,
            )
        except Exception as err:
            print(err)
            self.fail("validate_certificate_chain failed when it should have succeeded")

    def test_passes_on_empty_root_certs_array(self):
        try:
            validate_certificate_chain(
                x5c=apple_x5c_certs,
                pem_root_certs_bytes=[],
            )
        except Exception as err:
            print(err)
            self.fail("validate_certificate_chain failed when it should have succeeded")

    def test_includes_original_exception_when_raising(self):
        """
        A low-effort attempt at ensuring that the attempt to validate a certificate chain will
        include the original exception raised by the X509 validation library, instead of just its
        message.
        """
        custom_exception = X509StoreContextError(message="Oops", certificate=X509(), errors=[])

        with patch(
            "OpenSSL.crypto.X509StoreContext.verify_certificate", side_effect=custom_exception
        ):
            with self.assertRaises(InvalidCertificateChain) as ctx:
                validate_certificate_chain(
                    x5c=apple_x5c_certs,
                    pem_root_certs_bytes=[apple_webauthn_root_ca],
                )

            cause = ctx.exception.__cause__
            self.assertEqual(cause, custom_exception)

    @patch_validate_certificate_chain_x509store_getter
    def test_handles_cert_with_der_violation(self, patched_x509store: X509Store):
        """
        Some X.509 certificate extension(s) explicitly encode Extension.critical as FALSE, in
        violation of ASN.1 DER. This test demonstrates the ability to still handle such certificates
        by using more lenient BER instead.
        """
        x5c = [
            # x5c[0] is the one that breaks when trying to parse its ASN.1 structure using DER
            "MIID9jCCAmCgAwIBAgIBATALBgkqhkiG9w0BAQswOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA4YmM3NDljNzljZTI2M2JhZWU4Mzk4MGUzYWMzYjA5ODAeFw03MDAxMDEwMDAwMDBaFw00MDEyMzExNTU5NTlaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXEG0W2FVdhLgKOiZIALhInYRztj3WfUScPEUURuNbpkpXPjJ7+cUDb+vb3hLXOZ/9oGmDanb071tFB6qHEFGPaOCAXAwggFsMA4GA1UdDwEB/wQEAwIAgDCCAVgGCisGAQQB1nkCAREBAQAEggFFMIIBQQIBAwoBAQIBKQoBAQQg5PdENrEy/qA83J1g9S/sNRgWk2jEP7XcxTeL1OnbicQEADB3v4U9CAIGAZ6zlWkwv4VFZwRlMGMxPTAbBBZjb20uZ29vZ2xlLmFuZHJvaWQuZ3NmAgEiMB4EFmNvbS5nb29nbGUuYW5kcm9pZC5nbXMCBA+eRrUxIgQg8P1sW0EPJcslw7UzRsiXL64w+O50Ed+RBICtay1g24MwgZWhBTEDAgECogMCAQOjBAICAQClBTEDAgEEqgMCAQG/g3gDAgEDv4N5AwIBCr+FPgMCAQC/hUBMMEoEIKYU4CcUa00TICoOSLUeRawNqsWxi4oQz4Mh4hCAk4z+AQH/CgEABCAtDIeecTRGo7jpxGHABTqkluIgRVVZIcDf5RXV9rnym7+FQQUCAwIi4L+FQgUCAwMXazALBgkqhkiG9w0BAQsDggGBABBp2lD6ayRxjJdroWD6qrvNEQvDWsVONCiXolivI5W3U1oPf1DRVk4a8eupBSbqg6u45SHKnE5MjbMEysR+zJsvZqZx6/a860FJqEc8PvgrQny5UmGUIuq7mNP+N3fsVI8hS2rzXc0DtQLDLCom5j1GEMUPimI+gWJXyAy5d5y8pmutX7AYk45a44o8zlWNWjEzyo80SxET1XQz0kPCAgw5SB/nRZ05nmY7KYAaWf5TRXda8iLmRNcSw+W7AFzl8s3DKrRk5wIvNNAu0ixg6fcTGoj7lDfYpqKdQ2UDmO6A50acRvTvLTopRPGOl4ZcgyDi1AU9F+sI9YGqoWmNw7KxSdaKvnuKT71MJUpWS0iG9dq+z1QrFBaRq5CXXRmdOr4IbI0t0oHU3v/hfmvsL5kxE/p8Zi8id0L9PqQCWAFTNNLpsPV31Z6MSPHX2uqjSxWJ5TbsaY/AytS18dsPEhc9HDy4Zkac4UE3efs3DGRn/9gJQaTOJIZQu6NJ0ALjiQ==",
            # x5c[1] and x5c[2] _can_ be parsed using DER but of course parse using BER too
            "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",
        ]
        # Set to a day around when these certs were captured
        patched_x509store.set_time(datetime(2026, 6, 11, 0, 0, 0))

        try:
            validated = validate_certificate_chain(
                x5c=[urlsafe_b64decode(cert) for cert in x5c],
                pem_root_certs_bytes=[google_hardware_attestation_root_4],
            )
            self.assertTrue(validated)
        except Exception as err:
            print(err)
            self.fail("validate_certificate_chain failed when it should have succeeded")
