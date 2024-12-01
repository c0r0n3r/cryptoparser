# -*- coding: utf-8 -*-

import unittest


from cryptodatahub.common.algorithm import Authentication, MAC, Signature
from cryptodatahub.common.exception import InvalidValue


class TestAlgortihmOIDBase(unittest.TestCase):
    def test_error_not_found(self):
        with self.assertRaisesRegex(InvalidValue, '\'1.2.3.4.5.6.7.8\' is not a valid Authentication oid value'):
            Authentication.from_oid('1.2.3.4.5.6.7.8')

    def test_from_oid(self):
        self.assertEqual(
            Authentication.from_oid(Authentication.RSA.value.oid),
            Authentication.RSA
        )


class TestAlgortihmParam(unittest.TestCase):
    def test_str(self):
        self.assertEqual(str(Signature.RSA_WITH_SHA2_224.value), 'SHA-224 with RSA Encryption')


class TestMAC(unittest.TestCase):
    def test_digest_size(self):
        self.assertEqual(MAC.SHA2_256.value.digest_size, 256)
        self.assertEqual(MAC.POLY1305.value.digest_size, 128)
