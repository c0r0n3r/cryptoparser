# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.version import TlsProtocolVersionDraft, TlsProtocolVersionFinal, TlsVersion


class TestTlsCipherSuite(unittest.TestCase):
    def test_as_markdown(self):
        for cipher_suite in filter(lambda cipher_suite: cipher_suite.value.iana_name, TlsCipherSuite):
            self.assertIn(cipher_suite.value.iana_name, cipher_suite.value.as_markdown())

        for cipher_suite in filter(lambda cipher_suite: cipher_suite.value.iana_name is None, TlsCipherSuite):
            self.assertIn(cipher_suite.name, cipher_suite.value.as_markdown())

        for cipher_suite in filter(lambda cipher_suite: cipher_suite.value.openssl_name, TlsCipherSuite):
            self.assertIn(cipher_suite.value.openssl_name, cipher_suite.value.as_markdown())

    def test_min_version(self):
        self.assertEqual(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256.value.min_version,  # pylint: disable=no-member
            TlsProtocolVersionDraft(1)
        )
        self.assertEqual(
            TlsCipherSuite.TLS_RSA_WITH_NULL_SHA256.value.min_version,  # pylint: disable=no-member
            TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        )
