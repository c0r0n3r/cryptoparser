#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionDraft, TlsProtocolVersionFinal
from cryptoparser.ssh.version import SshVersion, SshProtocolVersion


class TestSshVersion(unittest.TestCase):
    def test_error(self):
        parsable = b'3.0'
        expected_error_message = '3 is not a valid SshVersion'
        with six.assertRaisesRegex(self, ValueError, expected_error_message):
            # pylint: disable=expression-not-assigned
            SshProtocolVersion.parse_exact_size(parsable)

        expected_error_message = 'b\'.0\' is not a valid SshProtocolVersion'
        with six.assertRaisesRegex(self, InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            SshProtocolVersion.parse_exact_size(b'.0')

        expected_error_message = 'b\'2.\' is not a valid SshProtocolVersion'
        with six.assertRaisesRegex(self, InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            SshProtocolVersion.parse_exact_size(b'2.')

    def test_parse(self):
        version = SshProtocolVersion.parse_exact_size(b'1.0')
        self.assertEqual(version, SshProtocolVersion(SshVersion.SSH1))
        self.assertEqual(version.supported_versions, [SshVersion.SSH1, ])

        version = SshProtocolVersion.parse_exact_size(b'1.99')
        self.assertEqual(version, SshProtocolVersion(SshVersion.SSH1, 99))
        self.assertEqual(version.supported_versions, [SshVersion.SSH1, SshVersion.SSH2])

        version = SshProtocolVersion.parse_exact_size(b'2.0')
        self.assertEqual(version, SshProtocolVersion(SshVersion.SSH2))
        self.assertEqual(version.supported_versions, [SshVersion.SSH2, ])

    def test_compose(self):
        self.assertEqual(b'2.0', SshProtocolVersion(SshVersion.SSH2, 0).compose())
        self.assertEqual(b'1.1', SshProtocolVersion(SshVersion.SSH1, 1).compose())

    def test_lt(self):
        self.assertLess(
            SshProtocolVersion(SshVersion.SSH1),
            SshProtocolVersion(SshVersion.SSH2)
        )

        self.assertLess(
            SshProtocolVersion(SshVersion.SSH2, 0),
            SshProtocolVersion(SshVersion.SSH2, 1)
        )

        self.assertLess(
            SshProtocolVersion(SshVersion.SSH1, 1),
            SshProtocolVersion(SshVersion.SSH2, 0)
        )

        self.assertGreater(
            SshProtocolVersion(SshVersion.SSH2, 0),
            SshProtocolVersion(SshVersion.SSH1, 1)
        )

    def test_eq(self):
        self.assertEqual(
            SshProtocolVersion(SshVersion.SSH1, 0),
            SshProtocolVersion(SshVersion.SSH1, 0)
        )

        self.assertEqual(
            SshProtocolVersion(SshVersion.SSH2, 0),
            SshProtocolVersion(SshVersion.SSH2, 0)
        )
