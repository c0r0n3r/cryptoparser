#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.common.exception import TooMuchData, InvalidValue

from cryptoparser.ssh.subprotocol import SshProtocolMessage
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion


class TestProtocolMessage(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(InvalidValue) as context_manager:
            SshProtocolMessage.parse_exact_size(b'ABC')
        self.assertEqual(context_manager.exception.value, 'ABC')

        with self.assertRaises(InvalidValue) as context_manager:
            SshProtocolMessage.parse_exact_size(b'SSH-2.0\r\n')
        self.assertEqual(context_manager.exception.value, b'\r')

        with self.assertRaises(InvalidValue) as context_manager:
            SshProtocolMessage.parse_exact_size(b'SSH-2.0-software_version\r')
        self.assertEqual(context_manager.exception.value, b'software_version\r')

        with self.assertRaises(TooMuchData) as context_manager:
            SshProtocolMessage.parse_exact_size(b'SSH-2.0-software_version ' + b'X' * 255 + b'\r\n')
        self.assertEqual(context_manager.exception.bytes_needed, len(b'SSH-2.0-software_version ') + len(b'\r\n'))

    def test_parse(self):
        message = SshProtocolMessage.parse_exact_size(b'SSH-1.1-software_version\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH1, 1))
        self.assertEqual(message.software_version, 'software_version')
        self.assertEqual(message.comment, None)

        message = SshProtocolMessage.parse_exact_size(b'SSH-2.2-software_version\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH2, 2))
        self.assertEqual(message.software_version, 'software_version')
        self.assertEqual(message.comment, None)

        message = SshProtocolMessage.parse_exact_size(b'SSH-2.0-software_version comment\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH2, 0))
        self.assertEqual(message.software_version, 'software_version')
        self.assertEqual(message.comment, 'comment')

        message = SshProtocolMessage.parse_exact_size(b'SSH-2.0-software_version comment with spaces\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH2, 0))
        self.assertEqual(message.software_version, 'software_version')
        self.assertEqual(message.comment, 'comment with spaces')

    def test_software_version(self):
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), software_version=u'αβγ')
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), software_version=u'software_version ')
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), software_version=u'software_version\r')
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), software_version=u'software_version\n')

    def test_comment(self):
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), 'software_version', comment=u'αβγ')
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), 'software_version', comment=u'comment\r')
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), 'software_version', comment=u'comment\n')

    def test_compose(self):
        self.assertEqual(
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                'software_version'
            ).compose(),
            b'SSH-2.2-software_version\r\n'
        )

        self.assertEqual(
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                'software_version',
                'comment'
            ).compose(),
            b'SSH-2.2-software_version comment\r\n'
        )

        self.assertEqual(
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                'software_version',
                'comment with spaces'
            ).compose(),
            b'SSH-2.2-software_version comment with spaces\r\n'
        )
