# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion


class TestTlsCipherSuite(unittest.TestCase):
    def test_str(self):
        for cipher_suite in filter(lambda cipher_suite: cipher_suite.value.iana_name, TlsCipherSuite):
            self.assertIn(cipher_suite.value.iana_name, str(cipher_suite.value))

        for cipher_suite in filter(lambda cipher_suite: cipher_suite.value.iana_name is None, TlsCipherSuite):
            self.assertIn(cipher_suite.name, str(cipher_suite.value))

        for cipher_suite in filter(lambda cipher_suite: cipher_suite.value.openssl_name, TlsCipherSuite):
            self.assertIn(cipher_suite.value.openssl_name, str(cipher_suite.value))

    def test_initial_version(self):
        self.assertEqual(
            TlsProtocolVersion(TlsCipherSuite.TLS_AES_128_GCM_SHA256.value.initial_version),
            TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_15)
        )
        self.assertEqual(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256.value.initial_version,
            TlsVersion.TLS1_3_DRAFT_15
        )
        self.assertEqual(
            TlsProtocolVersion(TlsCipherSuite.TLS_RSA_WITH_NULL_SHA256.value.initial_version),
            TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            TlsCipherSuite.TLS_RSA_WITH_NULL_SHA256.value.initial_version,
            TlsVersion.TLS1_2
        )
