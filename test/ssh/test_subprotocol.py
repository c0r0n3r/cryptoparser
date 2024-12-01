#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import unittest


from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.key import PublicKey, PublicKeyParamsRsa
from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)

from cryptoparser.common.classes import LanguageTag
from cryptoparser.common.exception import TooMuchData

from cryptoparser.ssh.key import SshHostKeyRSA
from cryptoparser.ssh.subprotocol import (
    SshDHGroupExchangeInit,
    SshDHGroupExchangeGroup,
    SshDHGroupExchangeReply,
    SshDHGroupExchangeRequest,
    SshDHKeyExchangeInit,
    SshDHKeyExchangeReply,
    SshKeyExchangeInit,
    SshMessageVariantInit,
    SshMessageVariantKexDH,
    SshMessageVariantKexDHGroup,
    SshNewKeys,
    SshProtocolMessage,
    SshUnimplementedMessage,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshSoftwareVersionUnparsed, SshVersion


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
        self.assertEqual(message.software_version, SshSoftwareVersionUnparsed('software_version'))
        self.assertEqual(message.comment, None)

        message = SshProtocolMessage.parse_exact_size(b'SSH-2.2-software_version\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH2, 2))
        self.assertEqual(message.software_version, SshSoftwareVersionUnparsed('software_version'))
        self.assertEqual(message.comment, None)

        message = SshProtocolMessage.parse_exact_size(b'SSH-2.0-software_version comment\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH2, 0))
        self.assertEqual(message.software_version, SshSoftwareVersionUnparsed('software_version'))
        self.assertEqual(message.comment, 'comment')

        message = SshProtocolMessage.parse_exact_size(b'SSH-2.0-software_version comment with spaces\r\n')
        self.assertEqual(message.protocol_version, SshProtocolVersion(SshVersion.SSH2, 0))
        self.assertEqual(message.software_version, SshSoftwareVersionUnparsed('software_version'))
        self.assertEqual(message.comment, 'comment with spaces')

    def test_comment(self):
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                SshSoftwareVersionUnparsed('software_version'),
                comment='αβγ',
            )
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                SshSoftwareVersionUnparsed('software_version'),
                comment='comment\r',
            )
        with self.assertRaises(InvalidValue):
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                SshSoftwareVersionUnparsed('software_version'),
                comment='comment\n',
            )

    def test_compose(self):
        self.assertEqual(
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                SshSoftwareVersionUnparsed('software_version'),
            ).compose(),
            b'SSH-2.2-software_version\r\n'
        )

        self.assertEqual(
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                SshSoftwareVersionUnparsed('software_version'),
                'comment'
            ).compose(),
            b'SSH-2.2-software_version comment\r\n'
        )

        self.assertEqual(
            SshProtocolMessage(
                SshProtocolVersion(SshVersion.SSH2, 2),
                SshSoftwareVersionUnparsed('software_version'),
                'comment with spaces'
            ).compose(),
            b'SSH-2.2-software_version comment with spaces\r\n'
        )


class TestKeyExchangeInitMessage(unittest.TestCase):
    def setUp(self):
        self.key_exchange_init_bytes = bytes(
            b'\x14' +                                               # message_code = SshMessageCode.KEXINIT
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +                   # cookie
            b'\x00\x00\x00\x3d' +
            b'diffie-hellman-group1-sha1,ecdh-sha2-nistp256,unparsable-algo' +  # kex_algorithms
            b'\x00\x00\x00\x2f' +
            b'ssh-ed25519,ecdsa-sha2-nistp256,unparsable-algo' +    # host_key_algorithms
            b'\x00\x00\x00\x31' +
            b'aes128-cbc,aes256-gcm@openssh.com,unparsable-algo' +  # encryption_algorithms_client_to_server
            b'\x00\x00\x00\x31' +
            b'aes256-gcm@openssh.com,aes128-cbc,unparsable-algo' +  # encryption_algorithms_server_to_client
            b'\x00\x00\x00\x2e' +
            b'hmac-sha1,umac-128@openssh.com,unparsable-algo' +     # mac_algorithms_client_to_server
            b'\x00\x00\x00\x2e' +
            b'umac-128@openssh.com,hmac-sha1,unparsable-algo' +     # mac_algorithms_server_to_client
            b'\x00\x00\x00\x25' +
            b'none,zlib@openssh.com,unparsable-algo' +              # compression_algorithms_client_to_server
            b'\x00\x00\x00\x25' +
            b'zlib@openssh.com,none,unparsable-algo' +              # compression_algorithms_server_to_client
            b'\x00\x00\x00\x0b' +
            b'en-UK,en-US' +                                        # languages_client_to_server
            b'\x00\x00\x00\x0b' +
            b'en-US,en-UK' +                                        # languages_server_to_client
            b'\x00' +                                               # first_kex_packet_follows
            b'\x00\x01\x02\x03' +                                   # reserved
            b''
        )
        self.key_exchange_init = SshKeyExchangeInit(
            kex_algorithms=[
                SshKexAlgorithm.DIFFIE_HELLMAN_GROUP1_SHA1,
                SshKexAlgorithm.ECDH_SHA2_NISTP256,
                'unparsable-algo',
            ],
            host_key_algorithms=[
                SshHostKeyAlgorithm.SSH_ED25519,
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                'unparsable-algo',
            ],
            encryption_algorithms_client_to_server=[
                SshEncryptionAlgorithm.AES128_CBC,
                SshEncryptionAlgorithm.AES256_GCM_OPENSSH_COM,
                'unparsable-algo',
            ],
            encryption_algorithms_server_to_client=[
                SshEncryptionAlgorithm.AES256_GCM_OPENSSH_COM,
                SshEncryptionAlgorithm.AES128_CBC,
                'unparsable-algo',
            ],
            mac_algorithms_client_to_server=[
                SshMacAlgorithm.HMAC_SHA1,
                SshMacAlgorithm.UMAC_128_OPENSSH_COM,
                'unparsable-algo',
            ],
            mac_algorithms_server_to_client=[
                SshMacAlgorithm.UMAC_128_OPENSSH_COM,
                SshMacAlgorithm.HMAC_SHA1,
                'unparsable-algo',
            ],
            compression_algorithms_client_to_server=[
                SshCompressionAlgorithm.NONE,
                SshCompressionAlgorithm.ZLIB_OPENSSH_COM,
                'unparsable-algo',
            ],
            compression_algorithms_server_to_client=[
                SshCompressionAlgorithm.ZLIB_OPENSSH_COM,
                SshCompressionAlgorithm.NONE,
                'unparsable-algo',
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
        SshMessageVariantInit.parse_exact_size(self.key_exchange_init_bytes)

    def test_compose(self):
        self.assertEqual(self.key_exchange_init.compose(), self.key_exchange_init_bytes)

    def test_hassh(self):
        self.assertEqual(self.key_exchange_init.hassh, 'cc40dc455f685d8f57f8794262e30422')
        self.assertEqual(self.key_exchange_init.hassh_server, '55a954fe89f7f04218e3013996beee76')


class TestUnimplementedMessage(unittest.TestCase):
    def setUp(self):
        self.unimplemented_bytes = bytes(
            b'\x03' +                           # message_code = SshMessageCode.UNIMPLEMENTED
            b'\x01\x02\x03\x04' +               # sequence_number
            b''
        )
        self.unimplemented = SshUnimplementedMessage(
            sequence_number=0x01020304
        )

    def test_parse(self):
        message = SshMessageVariantInit.parse_exact_size(self.unimplemented_bytes)
        self.assertEqual(message.sequence_number, 0x01020304)

    def test_compose(self):
        self.assertEqual(self.unimplemented.compose(), self.unimplemented_bytes)


class TestDHKeyExchangeInit(unittest.TestCase):
    def setUp(self):
        self.dh_key_exchange_init_bytes = bytes(
            b'\x1e' +                              # message_code = SshMessageCode.DH_KEX_INIT
            b'\x00\x00\x00\x10' +                  # ephemeral_public_key length
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +  # ephemeral_public_key length
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
            b''
        )
        self.dh_key_exchange_init = SshDHKeyExchangeInit(
            ephemeral_public_key=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )

    def test_parse(self):
        message = SshMessageVariantKexDH.parse_exact_size(self.dh_key_exchange_init_bytes)
        self.assertEqual(message.ephemeral_public_key, self.dh_key_exchange_init.ephemeral_public_key)

    def test_compose(self):
        self.assertEqual(self.dh_key_exchange_init.compose(), self.dh_key_exchange_init_bytes)


class TestDHGroupExchangeInit(unittest.TestCase):
    def setUp(self):
        self.dh_group_exchange_init_bytes = bytes(
            b'\x20' +                              # message_code = SshMessageCode.DH_KEX_INIT
            b'\x00\x00\x00\x10' +                  # ephemeral_public_key length
            b'\x00\x01\x02\x03\x04\x05\x06\x07' +  # ephemeral_public_key length
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
            b''
        )
        self.dh_group_exchange_init = SshDHGroupExchangeInit(
            ephemeral_public_key=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        )

    def test_parse(self):
        message = SshMessageVariantKexDHGroup.parse_exact_size(self.dh_group_exchange_init_bytes)
        self.assertEqual(message, self.dh_group_exchange_init)

    def test_compose(self):
        self.assertEqual(self.dh_group_exchange_init.compose(), self.dh_group_exchange_init_bytes)


class TestDHKeyExchangeReply(unittest.TestCase):
    def setUp(self):
        self.dh_key_exchange_reply_dict = collections.OrderedDict([
            ('message_code', b'\x1f'),  # DH_KEX_REPLY
            ('host_key_length', b'\x00\x00\x00\x23'),
            ('host_public_key', (
                b'\x00\x00\x00\x07' +
                b'ssh-rsa' +
                b'\x00\x00\x00\x08' +
                b'\x01\x01\x02\x03\x04\x05\x06\x07' +
                b'\x00\x00\x00\x08' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
            ('ephemeral_public_key_length', b'\x00\x00\x00\x10'),
            ('ephemeral_public_key', (
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
            ('signature_length', b'\x00\x00\x00\x10'),
            ('signature_key', (
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
        ])
        self.dh_key_exchange_reply_bytes = b''.join(self.dh_key_exchange_reply_dict.values())
        self.dh_key_exchange_reply = SshDHKeyExchangeReply(
            host_public_key=SshHostKeyRSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
                public_key=PublicKey.from_params(PublicKeyParamsRsa(
                    modulus=0x08090a0b0c0d0e0f,
                    public_exponent=0x0101020304050607,
                )),
            ),
            ephemeral_public_key=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            signature=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
        )

    def test_parse(self):
        message = SshMessageVariantKexDH.parse_exact_size(self.dh_key_exchange_reply_bytes)
        self.assertEqual(message, self.dh_key_exchange_reply)

    def test_compose(self):
        self.assertEqual(self.dh_key_exchange_reply.compose(), self.dh_key_exchange_reply_bytes)


class TestDHGroupExchangeReply(unittest.TestCase):
    def setUp(self):
        self.dh_group_exchange_reply_dict = collections.OrderedDict([
            ('message_code', b'\x21'),  # DH_GEX_REPLY
            ('host_key_length', b'\x00\x00\x00\x23'),
            ('host_public_key', (
                b'\x00\x00\x00\x07' +
                b'ssh-rsa' +
                b'\x00\x00\x00\x08' +
                b'\x01\x01\x02\x03\x04\x05\x06\x07' +
                b'\x00\x00\x00\x08' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
            ('ephemeral_public_key_length', b'\x00\x00\x00\x10'),
            ('ephemeral_public_keylic_key', (
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
            ('signature_length', b'\x00\x00\x00\x10'),
            ('signature_key', (
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
        ])
        self.dh_group_exchange_reply_bytes = b''.join(self.dh_group_exchange_reply_dict.values())
        self.dh_group_exchange_reply = SshDHGroupExchangeReply(
            host_public_key=SshHostKeyRSA(
                host_key_algorithm=SshHostKeyAlgorithm.SSH_RSA,
                public_key=PublicKey.from_params(PublicKeyParamsRsa(
                    modulus=0x08090a0b0c0d0e0f,
                    public_exponent=0x0101020304050607,
                )),
            ),
            ephemeral_public_key=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            signature=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
        )

    def test_parse(self):
        message = SshMessageVariantKexDHGroup.parse_exact_size(self.dh_group_exchange_reply_bytes)
        self.assertEqual(message, self.dh_group_exchange_reply)

    def test_compose(self):
        self.assertEqual(self.dh_group_exchange_reply.compose(), self.dh_group_exchange_reply_bytes)


class TestDHGroupExchangeRequest(unittest.TestCase):
    def setUp(self):
        self.dh_group_exchange_reply_dict = collections.OrderedDict([
            ('message_code', b'\x22'),  # DH_GEX_REQUEST
            ('gex_min', b'\x00\x00\x04\x00'),
            ('gex_number', b'\x00\x00\x08\x00'),
            ('gex_max', b'\x00\x00\x10\x00'),
        ])
        self.dh_group_exchange_reply_bytes = b''.join(self.dh_group_exchange_reply_dict.values())
        self.dh_group_exchange_reply = SshDHGroupExchangeRequest(
            gex_min=1024,
            gex_number=2048,
            gex_max=4096,
        )

    def test_parse(self):
        message = SshMessageVariantKexDHGroup.parse_exact_size(self.dh_group_exchange_reply_bytes)
        self.assertEqual(message, self.dh_group_exchange_reply)

    def test_compose(self):
        self.assertEqual(self.dh_group_exchange_reply.compose(), self.dh_group_exchange_reply_bytes)


class TestDHGroupExchangeGroup(unittest.TestCase):
    def setUp(self):
        self.dh_group_exchange_group_dict = collections.OrderedDict([
            ('message_code', b'\x1f'),  # DH_GEX_GROUP
            ('p_length', b'\x00\x00\x00\x10'),
            ('p', (
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
            ('g_length', b'\x00\x00\x00\x10'),
            ('g', (
                b'\x00\x01\x02\x03\x04\x05\x06\x07' +
                b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
                b''
            )),
        ])
        self.dh_group_exchange_group_bytes = b''.join(self.dh_group_exchange_group_dict.values())
        self.dh_group_exchange_group = SshDHGroupExchangeGroup(
            p=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            g=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
        )

    def test_parse(self):
        message = SshMessageVariantKexDHGroup.parse_exact_size(self.dh_group_exchange_group_bytes)
        self.assertEqual(message, self.dh_group_exchange_group)

    def test_compose(self):
        self.assertEqual(self.dh_group_exchange_group.compose(), self.dh_group_exchange_group_bytes)


class TestNewKeys(unittest.TestCase):
    def setUp(self):
        self.new_keys_dict = collections.OrderedDict([
            ('message_code', b'\x15'),  # NEWKEYS
        ])
        self.new_keys_bytes = b''.join(self.new_keys_dict.values())
        self.new_keys = SshNewKeys()

    def test_parse(self):
        message = SshNewKeys.parse_exact_size(self.new_keys_bytes)
        self.assertEqual(message, self.new_keys)

    def test_compose(self):
        self.assertEqual(self.new_keys.compose(), self.new_keys_bytes)
