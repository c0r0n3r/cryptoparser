# -*- coding: utf-8 -*-

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

    def test_asdict(self):
        certificate = self._get_public_key_x509('rsa8192.badssl.com_certificate.crt')
        dict_result = certificate._asdict()
        self.assertIn(
            Entity.GOOGLE,
            [sct.log.operator for sct in dict_result.pop('signed_certificate_timestamps')],
        )

        self.assertEqual(PublicKeyX509Base._asdict(certificate), dict_result)
