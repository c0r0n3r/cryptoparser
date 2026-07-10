# SPDX-License-Identifier: MPL-2.0

import hashlib

from test.common.classes import TestClasses

from cryptodatahub.common.key import PublicKeyX509Base
from cryptodatahub.common.entity import Entity

from cryptoparser.common.x509 import SignedCertificateTimestampList


class TestTlsPubKeys(TestClasses.TestKeyBase):
    def test_signed_certificate_timestamps(self):
        certificate = self._get_public_key_x509('rsa8192.badssl.com_root_ca.crt')
        self.assertEqual(certificate.signed_certificate_timestamps, SignedCertificateTimestampList([]))

        certificate = self._get_public_key_x509('rsa8192.badssl.com_certificate.crt')
        self.assertIn(
            Entity.GOOGLE,
            [sct.log.operator for sct in certificate.signed_certificate_timestamps]
        )

    def test_ja4x(self):
        certificate = self._get_public_key_x509('rsa8192.badssl.com_certificate.crt')
        ja4x = certificate.ja4x

        issuer_oid_hexes, subject_oid_hexes, extension_oid_hexes = ja4x.fingerprint_raw.split('_')
        # the subject relative distinguished names contain the common name (OID 2.5.4.3 -> 550403)
        self.assertIn('550403', subject_oid_hexes.split(','))
        self.assertIn('550403', issuer_oid_hexes.split(','))
        self.assertTrue(extension_oid_hexes)

        # the fingerprint is the per-section truncated SHA-256 of the raw OID lists
        self.assertEqual(ja4x.fingerprint, '_'.join(
            hashlib.sha256(oid_hexes.encode('ascii')).hexdigest()[:12]
            for oid_hexes in ja4x.fingerprint_raw.split('_')
        ))
        self.assertEqual(certificate.ja4x, ja4x)

    def test_asdict(self):
        certificate = self._get_public_key_x509('rsa8192.badssl.com_certificate.crt')
        dict_result = certificate._asdict()
        self.assertIn(
            Entity.GOOGLE,
            [sct.log.operator for sct in dict_result.pop('signed_certificate_timestamps')],
        )
        dict_result.pop('ja4x')

        self.assertEqual(PublicKeyX509Base._asdict(certificate), dict_result)
