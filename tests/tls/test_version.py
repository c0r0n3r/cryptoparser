#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionDraft, TlsProtocolVersionFinal


class TestTlsProtocolVersion(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(TypeError):
            TlsProtocolVersionBase(0x03, 0x03)

        with self.assertRaises(InvalidValue, msg='256 is not a valid TlsProtocolVersionDraft draft number value'):
            TlsProtocolVersionDraft(0x100)

        with self.assertRaises(InvalidValue, msg='-1 is not a valid TlsProtocolVersionDraft draft number value'):
            TlsProtocolVersionDraft(-1)

        with self.assertRaises(InvalidValue, msg='255 is not a valid TlsVersion'):
            TlsProtocolVersionFinal(0xff)

    def test_parse(self):
        self.assertEqual(
            TlsProtocolVersionFinal.parse_exact_size(b'\x03\x03'),
            TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )

        self.assertEqual(
            TlsProtocolVersionDraft.parse_exact_size(b'\x7f\x12'),
            TlsProtocolVersionDraft(18)
        )

        parsable = b'\x03\xff'
        expected_error_message = ' is not a valid TlsProtocolVersion'
        with six.assertRaisesRegex(self, InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            TlsProtocolVersionDraft.parse_exact_size(parsable)

        parsable = b'\x8f\x00'
        expected_error_message = ' is not a valid TlsProtocolVersion'
        with six.assertRaisesRegex(self, InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            TlsProtocolVersionDraft.parse_exact_size(b'\x8f\x00')

        with self.assertRaises(NotEnoughData) as context_manager:
            TlsProtocolVersionDraft.parse_exact_size(b'\xff')
        self.assertEqual(context_manager.exception.bytes_needed, 2)

    def test_compose(self):
        self.assertEqual(
            b'\x03\x03',
            TlsProtocolVersionFinal(TlsVersion.TLS1_2).compose()
        )

        self.assertEqual(
            b'\x7f\x12',
            TlsProtocolVersionDraft(18).compose()
        )

    def test_lt(self):
        self.assertLess(
            TlsProtocolVersionFinal(TlsVersion.TLS1_1),
            TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )

        self.assertLess(
            TlsProtocolVersionDraft(1),
            TlsProtocolVersionDraft(2)
        )

        self.assertLess(
            TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            TlsProtocolVersionDraft(0)
        )

        self.assertLess(
            TlsProtocolVersionDraft(255),
            TlsProtocolVersionFinal(TlsVersion.TLS1_3)
        )

    def test_set(self):
        self.assertEqual(
            2,
            len(set([
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2)
            ]))
        )
        self.assertEqual(
            1,
            len(set([
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1)
            ]))
        )

        self.assertEqual(
            2,
            len(set([
                TlsProtocolVersionDraft(1),
                TlsProtocolVersionDraft(2)
            ]))
        )
        self.assertEqual(
            1,
            len(set([
                TlsProtocolVersionDraft(1),
                TlsProtocolVersionDraft(1)
            ]))
        )


    def test_repr(self):
        self.assertEqual(repr(TlsProtocolVersionFinal(TlsVersion.SSL3)), 'ssl3')
        self.assertEqual(repr(TlsProtocolVersionFinal(TlsVersion.TLS1_0)), 'tls1')
        self.assertEqual(repr(TlsProtocolVersionFinal(TlsVersion.TLS1_2)), 'tls1_2')
        self.assertEqual(repr(TlsProtocolVersionDraft(24)), 'tls1_3_draft23')

    def test_str(self):
        self.assertEqual(str(TlsProtocolVersionFinal(TlsVersion.SSL3)), 'SSL 3.0')
        self.assertEqual(str(TlsProtocolVersionFinal(TlsVersion.TLS1_0)), 'TLS 1.0')
        self.assertEqual(str(TlsProtocolVersionFinal(TlsVersion.TLS1_2)), 'TLS 1.2')
        self.assertEqual(str(TlsProtocolVersionDraft(24)), 'TLS 1.3 Draft 23')
