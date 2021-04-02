# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.algorithm import Authentication, MAC, Signature
from cryptoparser.common.exception import InvalidValue


class TestAlgortihmOIDBase(unittest.TestCase):
    def test_error_not_found(self):
        with six.assertRaisesRegex(self, InvalidValue, '\'1.2.3.4.5.6.7.8\' is not a valid Authentication oid value'):
            Authentication.from_oid('1.2.3.4.5.6.7.8')

    def test_error_multiple_found(self):
        with six.assertRaisesRegex(self, InvalidValue, 'None is not a valid Authentication oid value'):
            Authentication.from_oid(None)

    def test_from_oid(self):
        self.assertEqual(
            Authentication.from_oid(Authentication.RSA.value.oid),
            Authentication.RSA
        )


class TestAlgortihmParam(unittest.TestCase):
    def test_markdown(self):
        self.assertEqual(Signature.RSA_WITH_SHA2_224.value.as_markdown(), 'SHA-224 with RSA Encryption')


class TestMAC(unittest.TestCase):
    def test_digest_size(self):
        self.assertEqual(MAC.SHA2_256.value.digest_size, 256)
        self.assertEqual(MAC.POLY1305.value.digest_size, 128)
