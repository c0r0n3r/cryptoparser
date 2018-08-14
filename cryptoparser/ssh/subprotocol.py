#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import base64
import binascii
import datetime
import enum
import random
import textwrap

from collections import OrderedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes as cryptography_hashes
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import _ssh_write_string
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, ParameterFormat
from cryptography.x509 import load_der_x509_certificate

from cryptoparser.common.algorithm import Authentication
from cryptoparser.common.base import JSONSerializable, VectorString, VectorParamString
from cryptoparser.common.exception import InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ParserText, ComposerText

from cryptoparser.ssh.ciphersuite import SshEncryptionAlgorithms, SshMacAlgorithms, SshKexAlgorithms, SshHostKeyAlgorithms, SshHostKeyType, SshCompressionAlgorithms, SshHostKeyAlgorithmFactory
from cryptoparser.ssh.version import SshProtocolVersion


class SshMessageCode(enum.IntEnum):
    DISCONNECT = 0x1
    IGNORE = 0x2
    UNIMPLEMENTED = 0x3
    DEBUG = 0x4
    SERVICE_REQUEST = 0x5
    SERVICE_ACCEPT = 0x6
    KEXINIT = 0x14
    NEWKEYS = 0x15
    ECDH_KEX_INIT = 0x1e
    ECDH_KEX_REPLY = 0x1f


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
        parser.parse_parsable('version', SshProtocolVersion)
        parser.parse_separator('-')
        parser.parse_string_until_separator_or_end('product', ' ')

        try:
            parser.parse_separator(' ')
        except InvalidValue:
            pass
        else:
            parser.parse_string_until_separator('comment', '\n')
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

        return composer.composed

    def __eq__(self, other):
        return (
            self.protocol_version == other.protocol_version and
            self.product == other.product and
            self.comment == other.comment
        )


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
        return SshKexAlgorithms


class SshHostKeyAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshHostKeyAlgorithms


class SshEncryptionAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshEncryptionAlgorithms


class SshMacAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshMacAlgorithms


class SshCompressionAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshCompressionAlgorithms


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

        composer.compose_bytes(self.cookie)

        for param_name, param_class in self._PARSABLES.items():
            composer.compose_parsable(getattr(self, param_name))

        composer.compose_numeric(1 if self.first_kex_packet_follows else 0, 1)
        composer.compose_numeric(self.reserved, 4)

        return composer.composed

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.KEXINIT


class SshDisconnectCode(enum.IntEnum):
    HOST_NOT_ALLOWED_TO_CONNECT = 0x01
    PROTOCOL_ERROR = 0x02
    KEY_EXCHANGE_FAILED = 0x03
    RESERVED = 0x04
    MAC_ERROR = 0x05
    COMPRESSION_ERROR = 0x06
    SERVICE_NOT_AVAILABLE = 0x07
    PROTOCOL_VERSION_NOT_SUPPORTED = 0x08
    HOST_KEY_NOT_VERIFIABLE = 0x09
    CONNECTION_LOST = 0x0a
    BY_APPLICATION = 0x0b
    TOO_MANY_CONNECTIONS = 0x0c
    AUTH_CANCELLED_BY_USER = 0x0d
    NO_MORE_AUTH_METHODS_AVAILABLE = 0x0e
    ILLEGAL_USER_NAME = 0x0f


class SshDisconnectMessage(SshMessageBase):
    def __init__(self, reason, description, language):
        self.reason = reason
        self.description = description
        self.language = language

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DISCONNECT

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('reason', 4, SshDisconnectCode)
        parser.parse_string('description', 4)
        parser.parse_string('language', 4)

        return SshDisconnectMessage(parser['reason'], parser['description'], parser['language']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        return composer.composed

class SshECDHKeyExchangeInit(SshMessageBase):
    def __init__(self, ephemeral_public_key):
        super(SshECDHKeyExchangeInit, self).__init__()

        self.key = ephemeral_public_key

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.ECDH_KEX_INIT

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        body_parser = ParserBinary(parsable[header_parser.parsed_length:])
        body_parser.parse_numeric('key_length', 4)
        body_parser.parse_bytes('ephemeral_public_key', body_parser['key_length'])

        ephemeral_public_key = load_der_public_key(body_parser['ephemeral_public_key'], backend=default_backend())

        return SshECDHKeyExchangeInit(ephemeral_public_key), header_parser.parsed_length + body_parser.parsed_length


    def compose(self):
        composer = self._compose_header()

        key_bytes = self.key.public_numbers().encode_point()
        #key_bytes = self.key.parameters().parameter_bytes(Encoding.DER, ParameterFormat.PKCS3)
        composer.compose_numeric(len(key_bytes), 4)
        composer.compose_bytes(key_bytes)

        return composer.composed


class SshHostKey(JSONSerializable, ParsableBase):
    def __init__(self, host_key_algorithm, host_public_key):
        self.host_public_key = host_public_key
        self.host_key_algorithm = host_key_algorithm

    def _get_hash(host_key_openssh, hash_algo):
        key_bytes = base64.b64decode(host_key_openssh)
        digest = cryptography_hashes.Hash(hash_algo(), default_backend())
        digest.update(key_bytes)
        if hash_algo == cryptography_hashes.MD5:
            hash_str = ':'.join(textwrap.wrap(str(binascii.hexlify(digest.finalize()), 'ascii'), 2))
        else:
            hash_str = str(base64.b64encode(digest.finalize()), 'ascii')

        return '{}:{}'.format(hash_algo.name.upper(), hash_str)

    @staticmethod
    def _get_hashes(host_key_openssh):
        hash_dict  = OrderedDict()

        for hash_algo in [ cryptography_hashes.SHA256, cryptography_hashes.SHA1, cryptography_hashes.MD5 ]:
            hash_dict[hash_algo.name] = SshHostKey._get_hash(host_key_openssh, hash_algo)

        return hash_dict

    @classmethod
    def _parse_rsa_public_key(cls, parser):
        parser.parse_numeric('exponent_length', 4)
        parser.parse_bytes('exponent', parser['exponent_length'])
        parser.parse_numeric('modulus_length', 4)
        parser.parse_bytes('modulus', parser['modulus_length'])

        exponent = int.from_bytes(parser['exponent'], byteorder='big', signed=False)
        modulus = int.from_bytes(parser['modulus'], byteorder='big', signed=False)

        return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())

    @classmethod
    def _parse_dss_public_key(cls, parser):
        integers = dict()
        for param_name in [ 'p', 'q', 'g', 'y' ]:
            param_length_name = param_name + '_length'
            parser.parse_numeric(param_length_name, 4)
            parser.parse_bytes(param_name, parser[param_length_name])
            integers[param_name] = int.from_bytes(parser[param_name], byteorder='big', signed=False)
        return dsa.DSAPublicNumbers(integers['y'], dsa.DSAParameterNumbers(integers['p'], integers['q'], integers['g'])).public_key(default_backend())

    @classmethod
    def _parse_ecdsa_public_key(cls, parser):
            parser.parse_numeric('curve_name_length', 4)
            parser.parse_bytes('curve_name', parser['curve_name_length'])

            curve = {
                b'ecdsa-sha2-nistp256': ec.SECP256R1,
                b'ecdsa-sha2-nistp384': ec.SECP384R1,
                b'ecdsa-sha2-nistp521': ec.SECP521R1,
                b'nistp256': ec.SECP256R1,
                b'nistp384': ec.SECP384R1,
                b'nistp521': ec.SECP521R1,
            }[bytes(parser['curve_name'])]()

            parser.parse_numeric('curve_data_length', 4)
            parser.parse_bytes('curve_data', parser['curve_data_length'])
            numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(curve, parser['curve_data'])
            return numbers.public_key(default_backend())

    @classmethod
    def _parse_eddsa_public_key(cls, parser):
        parser.parse_numeric('key_data_length', 4)
        parser.parse_bytes('key_data', parser['key_data_length'])

        return x25519.X25519PublicKey.from_public_bytes(bytes(parser['key_data']))

    def as_json(self):
        if isinstance(self.host_public_key, x25519.X25519PublicKey):
            key_size = None
            host_key_openssh = base64.b64encode(
                _ssh_write_string(b'ssh-ed25519') +
                _ssh_write_string(self.host_public_key.public_bytes())
            )
            host_key_openssh = str(host_key_openssh, 'ascii')
            hashes = self._get_hashes(host_key_openssh)
        else:
            key_size = self.host_public_key.key_size
            host_key_openssh = str(self.host_public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH), 'ascii').split(' ')[1]
            hashes = self._get_hashes(host_key_openssh)

        return {
            self.host_key_algorithm.value.code: OrderedDict([
            ('known_hosts', host_key_openssh),
            ('hashes', hashes),
            ('key_type', type(self.host_public_key).__name__[1:-len('PublicKey')]),
            ('key_size', key_size),
        ])}


    @classmethod
    def _parse(cls, parsable):
        return None, 0

    def compose(self):
        return b''


class SshCertificateType(enum.IntEnum):
    USER = 1
    HOST = 2


def utcfromtimestamp(time_t):
    try:
        value = datetime.datetime.utcfromtimestamp(time_t)
    except OverflowError:
        value = None
    else:
        if value == datetime.datetime(1970, 1, 1):
            value = None

    return value


class SshHostCertificate(SshHostKey):
    def __init__(self,
        host_key_algorithm,
        host_public_key,
        serial,
        key_type,
        key_id,
        valid_principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        reserved,
        signature_key,
        signature,
    ):
        super(SshHostCertificate, self).__init__(host_key_algorithm, host_public_key)

        self.serial = serial
        self.key_type = key_type
        self.key_id = key_id
        self.valid_principals = valid_principals
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.critical_options = critical_options
        self.extensions = extensions
        self._reserved = reserved
        self._signature_key = signature_key
        self._signature = signature

    def as_json(self):
        result = super(SshHostCertificate, self).as_json()

        result['serial'] = self.serial
        result['id'] = self.key_id
        result['valid_after'] = self.valid_after
        result['valid_before'] = self.valid_before

        return result

    @classmethod
    def _parse_ssh_key(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('host_key_algorithm_length', 4)
        parser.parse_parsable('host_key_type', SshHostKeyAlgorithmFactory)
        
        host_key_type = parser['host_key_type'].value

        if host_key_type.key_type == SshHostKeyType.CERTIFICATE:
            parser.parse_numeric('nonce_length', 4)
            parser.parse_bytes('nonce', parser['nonce_length'])

        if host_key_type.authentication == Authentication.ECDSA:
            host_key = cls._parse_ecdsa_public_key(parser)
        elif host_key_type.authentication == Authentication.RSA:
            host_key = cls._parse_rsa_public_key(parser)
        elif host_key_type.authentication == Authentication.DSS:
            host_key = cls._parse_dss_public_key(parser)
        elif host_key_type.authentication == Authentication.EDDSA:
            host_key = cls._parse_eddsa_public_key(parser)

        if host_key_type.key_type == SshHostKeyType.CERTIFICATE:
            parser.parse_numeric('serial', 8)
            parser.parse_numeric('type', 4, SshHostKeyType)
            parser.parse_string('key_id', 4)
            parser.parse_string('valid_principals', 4)
            parser.parse_numeric('valid_after', 8, utcfromtimestamp)
            parser.parse_numeric('valid_before', 8, utcfromtimestamp)
            parser.parse_numeric('critical_options_length', 4)
            parser.parse_bytes('critical_options', parser['critical_options_length'])
            parser.parse_numeric('extensions_length', 4)
            parser.parse_bytes('extensions', parser['extensions_length'])
            parser.parse_numeric('reserved_length', 4)
            parser.parse_bytes('reserved', parser['reserved_length'])
            parser.parse_numeric('signature_key_length', 4)
            parser.parse_bytes('signature_key', parser['signature_key_length'])
            parser.parse_numeric('signature_length', 4)
            parser.parse_bytes('signature', parser['signature_length'])

            return SshHostCertificate(
                parser['host_key_type'],
                host_key,
                parser['serial'] if parser['serial'] != 0 else None,
                parser['type'],
                parser['key_id'],
                parser['valid_principals'],
                parser['valid_after'],
                parser['valid_before'],
                parser['critical_options'],
                parser['extensions'],
                parser['reserved'],
                parser['signature_key'],
                parser['signature']
            ), parser.parsed_length
        else:
            return SshHostKey(
                parser['host_key_type'],
                host_key
            ), parser.parsed_length

    @classmethod
    def _parse(cls, parsable):
        host_key, parsed_length = cls._parse_ssh_key(parsable)
        host_key_algorithm = host_key.host_key_algorithm

        return host_key, parsed_length

    def compose(self):
        return b''

class SshX509Certificate(SshHostKey):
    def __init__(self,
        host_key_algorithm,
        x509_certificate,
    ):
        super(SshX509Certificate, self).__init__(host_key_algorithm, x509_certificate.public_key())

        self.x509_certificate = x509_certificate

class SshECDHKeyExchangeReply(SshMessageBase):
    def __init__(self, host_public_key, ephemeral_public_key):
        self.host_public_key = host_public_key
        self.ephemeral_public_key = ephemeral_public_key

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.ECDH_KEX_REPLY

    @classmethod
    def _parse_ssh_key(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('host_key_length', 4)

        parser.parse_parsable('host_public_key', SshHostCertificate)

        parser.parse_numeric('ephemeral_public_key_length', 4)
        parser.parse_bytes('ephemeral_public_key', parser['ephemeral_public_key_length'])
        ephemeral_public_key = None
        #ephemeral_public_key = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP521R1(), parser['ephemeral_public_key'])

        parser.parse_numeric('signature_length', 4)
        parser.parse_bytes('signature', parser['signature_length'])

        return parser['host_public_key'], parser['ephemeral_public_key'], parser.parsed_length

    @classmethod
    def _parse_x509_key(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('public_key_length', 4)
        parser.parse_bytes('public_key', parser['public_key_length'])

        parser.parse_numeric('ssh_key_length', 4)
        parser.parse_bytes('ssh_key', parser['ssh_key_length'])

        parser.parse_numeric('signature_length', 4)

        parser.parse_numeric('signature_type_length', 4)
        parser.parse_parsable('signature_type', SshHostKeyAlgorithmFactory)

        parser.parse_numeric('signature_data_length', 4)
        parser.parse_bytes('signature_data', parser['signature_data_length'])

        return SshX509Certificate(parser['signature_type'], load_der_x509_certificate(bytes(parser['public_key']), default_backend())), b'', parser.parsed_length

    @classmethod
    def _parse(cls, parsable):
        try:
            host_public_key, ephemeral_public_key, parsed_length = cls._parse_ssh_key(parsable)
        except InvalidValue:
            host_public_key, ephemeral_public_key, parsed_length = cls._parse_x509_key(parsable)

        return SshECDHKeyExchangeReply(
            host_public_key,
            ephemeral_public_key,
        ), parsed_length


    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(self.key.key_size / 8)
        composer.compose_bytes(self.key.public_bytes(Encoding.DER))

        return composer.composed
