#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.exception import NotEnoughData, InvalidValue

from cryptoparser.ssh.subprotocol import SshProtocolMessage
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion


class TestRecord(unittest.TestCase):
    def test_error(self):
        """
        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsAlertLevel'):
            # pylint: disable=expression-not-assigned
            SshProtocolMessage.parse_exact_size(b'\xff\x00'),

        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsAlertDescription'):
            # pylint: disable=expression-not-assigned
            SshProtocolMessage.parse_exact_size(b'\x01\xff'),

        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            SshProtocolMessage.parse_exact_size(b'\xff'),
        self.assertGreater(context_manager.exception.bytes_needed, 1)
        """
        pass

    def test_parse(self):
        self.assertEqual(
            SshProtocolMessage.parse_exact_size(b'SSH-2.1-Product' + b'\n'),
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 1), 'Product')
        )

        self.assertEqual(
            SshProtocolMessage.parse_exact_size(b'SSH-2.1-Product comment' + b'\n'),
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 1), 'Product', 'comment')
        )

    def test_compose(self):
        self.assertEqual(
            b'SSH-2.1-Product\n',
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 1), 'Product').compose()
        )

        self.assertEqual(
            b'SSH-2.1-Product comment\n',
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 1), 'Product', 'comment').compose()
        )
