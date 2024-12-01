#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import unittest


from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import Grade

from cryptoparser.common.parse import ParserText

from cryptoparser.ssh.version import (
    SshVersion,
    SshProtocolVersion,
    SshSoftwareVersionCryptlib,
    SshSoftwareVersionDropbear,
    SshSoftwareVersionIPSSH,
    SshSoftwareVersionMonacaSSH,
    SshSoftwareVersionOpenSSH,
    SshSoftwareVersionUnparsed,
    SshSoftwareVersionParsedVariant
)


class TestSshVersion(unittest.TestCase):
    def test_error(self):
        parsable = b'3.0'
        expected_error_message = '3 is not a valid SshVersion'
        with self.assertRaisesRegex(ValueError, expected_error_message):
            # pylint: disable=expression-not-assigned
            SshProtocolVersion.parse_exact_size(parsable)

        expected_error_message = '\'.0\' is not a valid SshProtocolVersion'
        with self.assertRaisesRegex(InvalidValue, expected_error_message):
            # pylint: disable=expression-not-assigned
            SshProtocolVersion.parse_exact_size(b'.0')

        expected_error_message = '\'2.\' is not a valid SshProtocolVersion'
        with self.assertRaisesRegex(InvalidValue, expected_error_message):
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

    def test_as_json(self):
        self.assertEqual(SshProtocolVersion(SshVersion.SSH1, 0).as_json(), '\"ssh1\"')
        self.assertEqual(SshProtocolVersion(SshVersion.SSH1, 1).as_json(), '\"ssh1\"')
        self.assertEqual(SshProtocolVersion(SshVersion.SSH2, 0).as_json(), '\"ssh2\"')
        self.assertEqual(SshProtocolVersion(SshVersion.SSH2, 1).as_json(), '\"ssh2\"')

    def test_str(self):
        self.assertEqual(str(SshProtocolVersion(SshVersion.SSH1, 0)), 'SSH 1.0')
        self.assertEqual(str(SshProtocolVersion(SshVersion.SSH1, 1)), 'SSH 1.1')
        self.assertEqual(str(SshProtocolVersion(SshVersion.SSH2, 0)), 'SSH 2.0')
        self.assertEqual(str(SshProtocolVersion(SshVersion.SSH2, 1)), 'SSH 2.1')

    def test_grade(self):
        self.assertEqual(SshProtocolVersion(SshVersion.SSH2).grade, Grade.SECURE)
        self.assertEqual(SshProtocolVersion(SshVersion.SSH1).grade, Grade.INSECURE)
        self.assertEqual(SshProtocolVersion(SshVersion.SSH1, 99).grade, Grade.INSECURE)


class TestSshSoftwareVersion(unittest.TestCase):
    @staticmethod
    def _get_software_version(raw):
        parser = ParserText(raw)
        parser.parse_parsable('software_version', SshSoftwareVersionParsedVariant)

        return parser['software_version']

    def test_parse(self):
        software_version = self._get_software_version(b'cryptlib')
        self.assertEqual(software_version.vendor, 'cryptlib')
        self.assertEqual(software_version, SshSoftwareVersionCryptlib())

        software_version = self._get_software_version(b'dropbear_2020.81')
        self.assertEqual(software_version.vendor, 'dropbear')
        self.assertEqual(software_version, SshSoftwareVersionDropbear('2020.81'))

        software_version = self._get_software_version(b'IPSSH-6.9.0')
        self.assertEqual(software_version.vendor, 'IPSSH')
        self.assertEqual(software_version, SshSoftwareVersionIPSSH('6.9.0'))

        software_version = self._get_software_version(b'Monaca')
        self.assertEqual(software_version.vendor, 'Monaca')
        self.assertEqual(software_version, SshSoftwareVersionMonacaSSH())

        software_version = self._get_software_version(b'OpenSSH_8.6')
        self.assertEqual(software_version.vendor, 'OpenSSH')
        self.assertEqual(software_version, SshSoftwareVersionOpenSSH('8.6'))

        parser = ParserText(b'unknown.ssh.server-1.2.3')
        parser.parse_parsable('software_version', SshSoftwareVersionUnparsed)
        software_version = parser['software_version']
        self.assertEqual(software_version.raw, 'unknown.ssh.server-1.2.3')

    def test_compose(self):
        software_version = SshSoftwareVersionCryptlib()
        self.assertEqual(software_version.compose(), b'cryptlib')
        self.assertEqual(
            software_version._asdict(),
            collections.OrderedDict([('vendor', 'cryptlib'), ('version', None)])
        )

        software_version = SshSoftwareVersionDropbear('2020.81')
        self.assertEqual(software_version.compose(), b'dropbear_2020.81')
        self.assertEqual(
            software_version._asdict(),
            collections.OrderedDict([('vendor', 'dropbear'), ('version', '2020.81')])
        )

        software_version = SshSoftwareVersionIPSSH('6.9.0')
        self.assertEqual(software_version.compose(), b'IPSSH-6.9.0')
        self.assertEqual(
            software_version._asdict(),
            collections.OrderedDict([('vendor', 'IPSSH'), ('version', '6.9.0')])
        )

        software_version = SshSoftwareVersionMonacaSSH()
        self.assertEqual(software_version.compose(), b'Monaca')
        self.assertEqual(
            software_version._asdict(),
            collections.OrderedDict([('vendor', 'Monaca'), ('version', None)])
        )

        software_version = SshSoftwareVersionOpenSSH('8.6')
        self.assertEqual(software_version.compose(), b'OpenSSH_8.6')
        self.assertEqual(
            software_version._asdict(),
            collections.OrderedDict([('vendor', 'OpenSSH'), ('version', '8.6')])
        )

        software_version = SshSoftwareVersionUnparsed('unknown.ssh.server-1.2.3')
        self.assertEqual(software_version.compose(), b'unknown.ssh.server-1.2.3')
        self.assertEqual(software_version.as_markdown(), 'unknown.ssh.server-1.2.3')

    def test_error_raw(self):
        with self.assertRaises(InvalidValue):
            SshSoftwareVersionUnparsed('αβγ')
        with self.assertRaises(InvalidValue):
            SshSoftwareVersionUnparsed('software_version ')
        with self.assertRaises(InvalidValue):
            SshSoftwareVersionUnparsed('software_version\r')
        with self.assertRaises(InvalidValue):
            SshSoftwareVersionUnparsed('software_version\n')
