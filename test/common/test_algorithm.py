# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.algorithm import Authentication
from cryptoparser.common.exception import InvalidValue


class TestAlgortihmOIDBase(unittest.TestCase):
    def test_error_not_found(self):
        with six.assertRaisesRegex(self, InvalidValue, '1.2.3.4.5.6.7.8 is not a valid Authentication oid value'):
            Authentication.from_oid('1.2.3.4.5.6.7.8')

    def test_error_multiple_found(self):
        with six.assertRaisesRegex(self, InvalidValue, 'None is not a valid Authentication oid value'):
            Authentication.from_oid(None)

    def test_from_oid(self):
        self.assertEqual(
            Authentication.from_oid(Authentication.RSA.value.oid),
            Authentication.RSA
        )
