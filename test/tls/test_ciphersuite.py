# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.version import TlsProtocolVersionDraft, TlsProtocolVersionFinal, TlsVersion


class TestTlsCipherSuite(unittest.TestCase):
    def test_min_version(self):
        self.assertEqual(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256.value.min_version,  # pylint: disable=no-member
            TlsProtocolVersionDraft(1)
        )
        self.assertEqual(
            TlsCipherSuite.TLS_RSA_WITH_NULL_SHA256.value.min_version,  # pylint: disable=no-member
            TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        )
