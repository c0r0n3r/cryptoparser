#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import random

from collections import OrderedDict

from cryptoparser.common.base import VectorString, VectorParamString, StringComposer
from cryptoparser.common.exception import InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ParserText, ComposerText
from cryptoparser.ssh.version import SshVersion


class SshMessageCode(enum.IntEnum):
    DISCONNECT = 0x1
    IGNORE = 0x2
    UNIMPLEMENTED = 0x3
    DEBUG = 0x4
    SERVICE_REQUEST = 0x5
    SERVICE_ACCEPT = 0x6
    KEXINIT = 0x14
    NEWKEYS = 0x15


import cryptoparser.common.utils as utils

class SshMessageBase(ParsableBase):
    @abc.abstractmethod
    def get_message_code(cls):
        raise NotImplementedError()

    def get_leaf_classes(cls):
        return utils.get_leaf_classes(cls)

    @classmethod
    def _parse_header(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('message_code', 1, SshMessageCode)

        if parser['message_code'] != cls.get_message_code():
            raise InvalidValue(parser['message_code'], SshMessageBase, 'message_code')

        return parser

    @classmethod
    def _compose_header(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.get_message_code(), 1)

        return composer


class SshProtocolMessage(ParsableBase):
    def __init__(self, protocol_version, product, comment=None):
        self.protocol_version = protocol_version
        self.product = product
        self.comment = comment

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_by_length('protocol', min_length=3, max_length=3)
        if parser['protocol'] != 'SSH':
            raise InvalidValue

        parser.parse_separator('-')
        parser.parse_parsable('version', SshVersion)
        parser.parse_separator('-')
        parser.parse_string_by_separator('product', ' ', optional_sparator=True)

        try:
            parser.parse_separator(' ')
        except InvalidValue:
            pass
        else:
            parser.parse_string_by_separator('comment', '\n')
            parser.parse_separator('\n')

        return SshProtocolMessage(
            parser['version'],
            parser['product'],
            parser['comment'] if hasattr(parser, 'comment') else None
        ), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string('SSH')
        composer.compose_separator('-')
        composer.compose_parsable(self.protocol_version)
        composer.compose_separator('-')
        composer.compose_string(self.product)
        if self.comment is not None:
            composer.compose_separator(' ')
            composer.compose_string(self.comment)
        composer.compose_separator('\n')

        return composer.composed.encode('ascii')


class SshEncryptionAlogrithms(StringComposer, enum.Enum):
    AES128_CBC = 'aes128-cbc'
    AES128_CTR = 'aes128-ctr'
    AES128_GCM_OPENSSH_COM = 'aes128-gcm@openssh.com'
    AES192_CBC = 'aes192-cbc'
    AES192_CTR = 'aes192-ctr'
    AES256_CBC = 'aes256-cbc'
    AES256_CTR = 'aes256-ctr'
    AES256_GCM_OPENSSH_COM = 'aes256-gcm@openssh.com'
    ARCFOUR = 'arcfour'
    ARCFOUR128 = 'arcfour128'
    ARCFOUR256 = 'arcfour256'
    BLOWFISH_CBC = 'blowfish-cbc'
    CAST128_CBC = 'cast128-cbc'
    CHACHA20_POLY1305_OPENSSH_COM = 'chacha20-poly1305@openssh.com'
    RIJNDAEL_CBC_LYSATOR_LIU_SE = 'rijndael-cbc@lysator-liu-se'
    TRIPLE_DES_CBC = '3des-cbc'


class SshMacAlogrithms(StringComposer, enum.Enum):
    HMAC_SHA1 = 'hmac-sha1'
    HMAC_SHA1_96 = 'hmac-sha1-96'
    HMAC_SHA2_256 = 'hmac-sha2-256'
    HMAC_SHA2_512 = 'hmac-sha2-512'
    HMAC_MD5 = 'hmac-md5'
    HMAC_MD5_96 = 'hmac-md5-96'
    UMAC_64_OPENSSH_COM = 'umac-64@openssh.com'
    UMAC_128_OPENSSH_COM = 'umac-128@openssh.com'
    HMAC_SHA1_ETM_OPENSSH_COM = 'hmac-sha1-etm@openssh.com'
    HMAC_SHA1_96_ETM_OPENSSH_COM = 'hmac-sha1-96-etm@openssh.com'
    HMAC_SHA2_256_ETM_OPENSSH_COM = 'hmac-sha2-256-etm@openssh.com'
    HMAC_SHA2_512_ETM_OPENSSH_COM = 'hmac-sha2-512-etm@openssh.com'
    HMAC_MD5_ETM_OPENSSH_COM = 'hmac-md5-etm@openssh.com'
    HMAC_MD5_96_ETM_OPENSSH_COM = 'hmac-md5-96-etm@openssh.com'
    UMAC_64_ETM_OPENSSH_COM = 'umac-64-etm@openssh.com'
    UMAC_128_ETM_OPENSSH_COM = 'umac-128-etm@openssh.com'


class SshKexAlogrithms(StringComposer, enum.Enum):
    DIFFIE_HELLMAN_GROUP1_SHA1 = 'diffie-hellman-group1-sha1'
    DIFFIE_HELLMAN_GROUP14_SHA1 = 'diffie-hellman-group14-sha1'
    DIFFIE_HELLMAN_GROUP14_SHA256 = 'diffie-hellman-group14-sha256'
    DIFFIE_HELLMAN_GROUP16_SHA512 = 'diffie-hellman-group16-sha512'
    DIFFIE_HELLMAN_GROUP18_SHA512 = 'diffie-hellman-group18-sha512'
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = 'diffie-hellman-group-exchange-sha1'
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 = 'diffie-hellman-group-exchange-sha256'
    ECDH_SHA2_NISTP256 = 'ecdh-sha2-nistp256'
    ECDH_SHA2_NISTP384 = 'ecdh-sha2-nistp384'
    ECDH_SHA2_NISTP521 = 'ecdh-sha2-nistp521'
    CURVE25519_SHA256 = 'curve25519-sha256'
    CURVE25519_SHA256_LIBSSH_RG = 'curve25519-sha256@libssh.org'
    GSS_GEX_SHA1_ = 'gss-gex-sha1_'
    GSS_GROUP1_SHA1_ = 'gss-group1-sha1_'
    GSS_GROUP14_SHA1_ = 'gss-group14-sha1_'
    GSS_GROUP14_SHA256_ = 'gss-group14-sha256_'
    GSS_GROUP16_SHA512_ = 'gss-group16-sha512_'
    GSS_NISTP256_SHA256_ = 'gss-nistp256-sha256_'
    GSS_CURVE25519_SHA256_ = 'gss-curve25519-sha256_'


class SshHostKeyAlogrithms(StringComposer, enum.Enum):
    SSH_ED25519 = 'ssh-ed25519'
    SSH_ED25519_CERT_V01_OPENSSH_COM = 'ssh-ed25519-cert-v01@openssh.com'
    SSH_RSA = 'ssh-rsa'
    RSA_SHA2_256 = 'rsa-sha2-256'
    RSA_SHA2_512 = 'rsa-sha2-512'
    SSH_DSS = 'ssh-dss'
    ECDSA_SHA2_NISTP256 = 'ecdsa-sha2-nistp256'
    ECDSA_SHA2_NISTP384 = 'ecdsa-sha2-nistp384'
    ECDSA_SHA2_NISTP521 = 'ecdsa-sha2-nistp521'
    SSH_RSA_CERT_V01_OPENSSH_COM = 'ssh-rsa-cert-v01@openssh.com'
    SSH_DSS_CERT_V01_OPENSSH_COM = 'ssh-dss-cert-v01@openssh.com'
    ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM = 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
    ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM = 'ecdsa-sha2-nistp384-cert-v01@openssh.com'
    ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM = 'ecdsa-sha2-nistp521-cert-v01@openssh.com'


class SshCompressionAlogrithms(StringComposer, enum.Enum):
    ZLIB_OPENSSH_COM = 'zlib@openssh.com'
    ZLIB = 'zlib'
    NONE = 'none'


class SshAlgorithmVector(VectorString):
    @classmethod
    def get_param(cls):
        return VectorParamString(
            min_byte_num=0,
            max_byte_num=2 ** 32 - 1,
            separator=',',
            item_class=cls.get_item_class(),
            fallback_class=str
        )

    @abc.abstractmethod
    def get_item_class(cls):
        raise NotImplementedError()


class SshKexAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshKexAlogrithms


class SshHostKeyAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshHostKeyAlogrithms


class SshEncryptionAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshEncryptionAlogrithms


class SshMacAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshMacAlogrithms


class SshCompressionAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshCompressionAlogrithms


class SshLanguageVector(VectorString):
    @classmethod
    def get_param(cls):
        return VectorParamString(
            min_byte_num=0,
            max_byte_num=2 ** 32 - 1,
            separator=',',
            item_class=str
        )


class SshKeyExchangeInit(SshMessageBase):
    _PARSABLES = OrderedDict([
        ('kex_algorithms', SshKexAlgorithmVector),
        ('server_host_key_algorithms', SshHostKeyAlgorithmVector),
        ('encryption_algorithms_client_to_server', SshEncryptionAlgorithmVector),
        ('encryption_algorithms_server_to_client', SshEncryptionAlgorithmVector),
        ('mac_algorithms_client_to_server', SshMacAlgorithmVector),
        ('mac_algorithms_server_to_client', SshMacAlgorithmVector),
        ('compression_algorithms_client_to_server', SshCompressionAlgorithmVector),
        ('compression_algorithms_server_to_client', SshCompressionAlgorithmVector),
        ('languages_client_to_server', SshLanguageVector),
        ('languages_server_to_client', SshLanguageVector),
    ])

    def __init__(
        self,
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
        languages_client_to_server=[],
        languages_server_to_client=[],
        first_kex_packet_follows=0,
        cookie=bytearray.fromhex('{:16x}'.format(random.getrandbits(128)).zfill(32)),
        reserved=0x00000000
    ):
        for param_name, param_class in self._PARSABLES.items():
            setattr(self, param_name, param_class(locals()[param_name]))

        self.first_kex_packet_follows = first_kex_packet_follows
        self.cookie = cookie
        self.reserved = reserved

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        body_parser = ParserBinary(parsable[header_parser.parsed_length:])

        body_parser.parse_bytes('cookie', 16)
        for param_name, param_class in cls._PARSABLES.items():
            body_parser.parse_parsable(param_name, param_class)

        body_parser.parse_numeric('first_kex_packet_follows', 1, bool)
        body_parser.parse_numeric('reserved', 4)

        return SshKeyExchangeInit(**body_parser), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(self.get_message_code(), 1)
        composer.compose_bytes(self.cookie)

        for param_name, param_class in self._PARSABLES.items():
            composer.compose_parsable(getattr(self, param_name))

        composer.compose_numeric(1 if self.first_kex_packet_follows else 0, 1)
        composer.compose_numeric(self.reserved, 4)

        return composer.composed

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.KEXINIT
