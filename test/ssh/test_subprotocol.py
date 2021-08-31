#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from cryptoparser.common.classes import LanguageTag
from cryptoparser.common.exception import TooMuchData, InvalidValue

from cryptoparser.ssh.ciphersuite import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)
from cryptoparser.ssh.subprotocol import SshProtocolMessage, SshKeyExchangeInit, SshHandshakeMessageVariant
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
            SshProtocolMessage(SshProtocolVersion(SshVersion.SSH2, 2), software_version=six.ensure_text('αβγ'))
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2), software_version=six.ensure_text('software_version ')
            )
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2), software_version=six.ensure_text('software_version\r')
            )
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2), software_version=six.ensure_text('software_version\n')
            )

    def test_comment(self):
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2), 'software_version', comment=six.ensure_text('αβγ')
            )
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2), 'software_version', comment=six.ensure_text('comment\r')
            )
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2), 'software_version', comment=six.ensure_text('comment\n')
            )

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


class TestKeyExchangeInitMessage(unittest.TestCase):
    def setUp(self):
        self.key_exchange_init_bytes = bytes(
            b'\x14' +                                           # message_code = SshMessageCode.KEXINIT
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +               # cookie
            b'\x00\x00\x00\x2d' +                               # kex_algorithms_length
            b'diffie-hellman-group1-sha1,ecdh-sha2-nistp256' +  # kex_algorithms
            b'\x00\x00\x00\x1f' +                               # host_key_algorithms_length
            b'ssh-ed25519,ecdsa-sha2-nistp256' +                # host_key_algorithms
            b'\x00\x00\x00\x21' +                               # encryption_algorithms_client_to_server_length
            b'aes128-cbc,aes256-gcm@openssh.com' +              # encryption_algorithms_client_to_server
            b'\x00\x00\x00\x21' +                               # encryption_algorithms_server_to_client_length
            b'aes256-gcm@openssh.com,aes128-cbc' +              # encryption_algorithms_server_to_client
            b'\x00\x00\x00\x1e' +                               # mac_algorithms_client_to_server_length
            b'hmac-sha1,umac-128@openssh.com' +                 # mac_algorithms_client_to_server
            b'\x00\x00\x00\x1e' +                               # mac_algorithms_server_to_client_length
            b'umac-128@openssh.com,hmac-sha1' +                 # mac_algorithms_server_to_client
            b'\x00\x00\x00\x15' +                               # compression_algorithms_client_to_server_length
            b'none,zlib@openssh.com' +                          # compression_algorithms_client_to_server
            b'\x00\x00\x00\x15' +                               # compression_algorithms_server_to_client_length
            b'zlib@openssh.com,none' +                          # compression_algorithms_server_to_client
            b'\x00\x00\x00\x0b' +                               # languages_client_to_server_length
            b'en-UK,en-US' +                                    # languages_client_to_server
            b'\x00\x00\x00\x0b' +                               # languages_server_to_client_length
            b'en-US,en-UK' +                                    # languages_server_to_client
            b'\x00' +                                           # first_kex_packet_follows
            b'\x00\x01\x02\x03' +                               # reserved
            b''
        )
        self.key_exchange_init = SshKeyExchangeInit(
            kex_algorithms=[
                SshKexAlgorithm.DIFFIE_HELLMAN_GROUP1_SHA1,
                SshKexAlgorithm.ECDH_SHA2_NISTP256,
            ],
            host_key_algorithms=[
                SshHostKeyAlgorithm.SSH_ED25519,
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
            ],
            encryption_algorithms_client_to_server=[
                SshEncryptionAlgorithm.AES128_CBC,
                SshEncryptionAlgorithm.AES256_GCM_OPENSSH_COM,
            ],
            encryption_algorithms_server_to_client=[
                SshEncryptionAlgorithm.AES256_GCM_OPENSSH_COM,
                SshEncryptionAlgorithm.AES128_CBC,
            ],
            mac_algorithms_client_to_server=[
                SshMacAlgorithm.HMAC_SHA1,
                SshMacAlgorithm.UMAC_128_OPENSSH_COM,
            ],
            mac_algorithms_server_to_client=[
                SshMacAlgorithm.UMAC_128_OPENSSH_COM,
                SshMacAlgorithm.HMAC_SHA1,
            ],
            compression_algorithms_client_to_server=[
                SshCompressionAlgorithm.NONE,
                SshCompressionAlgorithm.ZLIB_OPENSSH_COM,
            ],
            compression_algorithms_server_to_client=[
                SshCompressionAlgorithm.ZLIB_OPENSSH_COM,
                SshCompressionAlgorithm.NONE,
            ],
            languages_client_to_server=[
                LanguageTag('en', ['UK', ]),
                LanguageTag('en', ['US', ]),
            ],
            languages_server_to_client=[
                LanguageTag('en', ['US', ]),
                LanguageTag('en', ['UK', ]),
            ],
            cookie=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            reserved=0x00010203,
        )

    def test_parse(self):
        SshHandshakeMessageVariant.parse_exact_size(self.key_exchange_init_bytes)

    def test_compose(self):
        self.assertEqual(self.key_exchange_init.compose(), self.key_exchange_init_bytes)
