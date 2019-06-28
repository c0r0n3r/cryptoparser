# -*- coding: utf-8 -*-

import abc
import collections
import enum
import random

import attr
import six

from cryptoparser.common.base import (
    VariantParsable,
    VectorParamString,
    VectorString,
)
from cryptoparser.common.classes import LanguageTag
from cryptoparser.common.exception import InvalidValue, InvalidType, TooMuchData
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ParserText, ComposerText

from cryptoparser.ssh.ciphersuite import (
    SshKexAlgorithm,
    SshHostKeyAlgorithm,
    SshEncryptionAlgorithm,
    SshMacAlgorithm,
    SshCompressionAlgorithm,
)
from cryptoparser.ssh.key import SshPublicKeyBase, SshHostPublicKeyVariant
from cryptoparser.ssh.version import (
    SshProtocolVersion,
    SshSoftwareVersionBase,
    SshSoftwareVersionParsedVariant,
    SshSoftwareVersionUnparsed,
)


class SshMessageCode(enum.IntEnum):
    DISCONNECT = 0x1
    IGNORE = 0x2
    UNIMPLEMENTED = 0x3
    DEBUG = 0x4
    SERVICE_REQUEST = 0x5
    SERVICE_ACCEPT = 0x6
    KEXINIT = 0x14
    NEWKEYS = 0x15
    DH_KEX_INIT = 0x1e
    DH_KEX_REPLY = 0x1f
    DH_GEX_GROUP = 0x1f
    DH_GEX_INIT = 0x20
    DH_GEX_REPLY = 0x21
    DH_GEX_REQUEST = 0x22


class SshMessageBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_message_code(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('message_code', 1, SshMessageCode)

        if parser['message_code'] != cls.get_message_code():
            raise InvalidType()

        return parser

    @classmethod
    def _compose_header(cls):
        composer = ComposerBinary()

        composer.compose_numeric(cls.get_message_code(), 1)

        return composer


@attr.s
class SshProtocolMessage(ParsableBase):
    protocol_version = attr.ib(validator=attr.validators.instance_of(SshProtocolVersion))
    software_version = attr.ib(validator=attr.validators.instance_of(SshSoftwareVersionBase))
    comment = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)), default=None)

    @comment.validator
    def comment_validator(self, _, value):  # pylint: disable=no-self-use
        if value is not None:
            if '\r' in value or '\n' in value:
                raise InvalidValue(value, SshProtocolMessage, 'comment')
            try:
                value.encode('ascii')
            except UnicodeEncodeError as e:
                six.raise_from(InvalidValue(value, SshProtocolMessage, 'comment'), e)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_by_length('protocol', min_length=3, max_length=3)
        if parser['protocol'] != 'SSH':
            raise InvalidValue(parser['protocol'], SshProtocolMessage, 'protocol')

        parser.parse_string('separator', '-')
        parser.parse_parsable('protocol_version', SshProtocolVersion)
        parser.parse_string('separator', '-')

        parser.parse_string_until_separator('software_version_and_comment', '\n')
        software_version_and_comment = parser['software_version_and_comment'].split(' ')

        if software_version_and_comment[-1][-1] == '\r':
            software_version_and_comment[-1] = software_version_and_comment[-1][:-1]

        software_version_parser = ParserText(software_version_and_comment[0].encode('ascii'))
        try:
            software_version_parser.parse_parsable('value', SshSoftwareVersionParsedVariant)
        except InvalidValue:
            software_version_parser.parse_parsable('value', SshSoftwareVersionUnparsed)

        if len(software_version_and_comment) > 1:
            comment = ' '.join(software_version_and_comment[1:])
        else:
            comment = None
        parser.parse_separator('\n')

        if parser.parsed_length > 255:
            raise TooMuchData(parser.parsed_length - 255)

        return SshProtocolMessage(
            parser['protocol_version'],
            software_version_parser['value'],
            comment
        ), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string('SSH')
        composer.compose_separator('-')
        composer.compose_parsable(self.protocol_version)
        composer.compose_separator('-')
        composer.compose_string(self.software_version)
        if self.comment is not None:
            composer.compose_separator(' ')
            composer.compose_string(self.comment)
        composer.compose_separator('\r\n')

        return composer.composed


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

    @classmethod
    @abc.abstractmethod
    def get_item_class(cls):
        raise NotImplementedError()


class SshKexAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshKexAlgorithm


class SshHostKeyAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshHostKeyAlgorithm


class SshEncryptionAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshEncryptionAlgorithm


class SshMacAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshMacAlgorithm


class SshCompressionAlgorithmVector(SshAlgorithmVector):
    @classmethod
    def get_item_class(cls):
        return SshCompressionAlgorithm


class VectorParamSshLanguage(VectorParamString):
    def __init__(self):
        super(VectorParamSshLanguage, self).__init__(
            min_byte_num=0,
            max_byte_num=2 ** 32 - 1,
            separator=',',
            item_class=LanguageTag,
            fallback_class=None,
        )

    def get_item_size(self, item):
        return len(item.compose())


class SshLanguageVector(VectorString):
    @classmethod
    def get_param(cls):
        return VectorParamSshLanguage()


@attr.s  # pylint: disable=too-many-instance-attributes
class SshKeyExchangeInit(SshMessageBase):
    kex_algorithms = attr.ib(
        converter=SshKexAlgorithmVector,
        validator=attr.validators.instance_of(SshKexAlgorithmVector)
    )
    host_key_algorithms = attr.ib(
        converter=SshHostKeyAlgorithmVector,
        validator=attr.validators.instance_of(SshHostKeyAlgorithmVector)
    )
    encryption_algorithms_client_to_server = attr.ib(
        converter=SshEncryptionAlgorithmVector,
        validator=attr.validators.instance_of(SshEncryptionAlgorithmVector)
    )
    encryption_algorithms_server_to_client = attr.ib(
        converter=SshEncryptionAlgorithmVector,
        validator=attr.validators.instance_of(SshEncryptionAlgorithmVector)
    )
    mac_algorithms_client_to_server = attr.ib(
        converter=SshMacAlgorithmVector,
        validator=attr.validators.instance_of(SshMacAlgorithmVector)
    )
    mac_algorithms_server_to_client = attr.ib(
        converter=SshMacAlgorithmVector,
        validator=attr.validators.instance_of(SshMacAlgorithmVector)
    )
    compression_algorithms_client_to_server = attr.ib(
        converter=SshCompressionAlgorithmVector,
        validator=attr.validators.instance_of(SshCompressionAlgorithmVector)
    )
    compression_algorithms_server_to_client = attr.ib(
        converter=SshCompressionAlgorithmVector,
        validator=attr.validators.instance_of(SshCompressionAlgorithmVector)
    )
    languages_client_to_server = attr.ib(
        converter=SshLanguageVector,
        validator=attr.validators.instance_of(SshLanguageVector), default=()
    )
    languages_server_to_client = attr.ib(
        converter=SshLanguageVector,
        validator=attr.validators.instance_of(SshLanguageVector), default=()
    )
    first_kex_packet_follows = attr.ib(validator=attr.validators.instance_of(six.integer_types), default=0)
    cookie = attr.ib(
        validator=attr.validators.instance_of((bytearray, bytes)),
        default=bytearray.fromhex('{:16x}'.format(random.getrandbits(128)).zfill(32))
    )
    reserved = attr.ib(validator=attr.validators.instance_of(six.integer_types), default=0x00000000)

    @classmethod
    def _get_cipher_attributes(cls):
        for attribute in attr.fields(cls):
            if (attribute.validator and
                    isinstance(attribute.validator.type, type) and
                    issubclass(attribute.validator.type, ParsableBase)):
                yield attribute

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        body_parser = ParserBinary(parsable[header_parser.parsed_length:])

        body_parser.parse_raw('cookie', 16)
        for attribute in cls._get_cipher_attributes():
            body_parser.parse_parsable(attribute.name, attribute.validator.type)

        body_parser.parse_numeric('first_kex_packet_follows', 1, bool)
        body_parser.parse_numeric('reserved', 4)

        return SshKeyExchangeInit(**dict(body_parser)), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_raw(self.cookie)

        for attribute in self._get_cipher_attributes():
            composer.compose_parsable(getattr(self, attribute.name))

        composer.compose_numeric(1 if self.first_kex_packet_follows else 0, 1)
        composer.compose_numeric(self.reserved, 4)

        return composer.composed

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.KEXINIT


class SshReasonCode(enum.IntEnum):
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


@attr.s
class SshDisconnectMessage(SshMessageBase):
    reason = attr.ib(validator=attr.validators.instance_of(SshReasonCode))
    description = attr.ib(
        converter=six.text_type,
        validator=attr.validators.instance_of(six.string_types)
    )
    language = attr.ib(
        default='US',
        validator=attr.validators.instance_of(six.string_types)
    )

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DISCONNECT

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('reason', 4, SshReasonCode)
        parser.parse_string('description', 4, 'utf-8')
        parser.parse_string('language', 4, 'ascii')

        return SshDisconnectMessage(parser['reason'], parser['description'], parser['language']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(self.reason.value, 4)
        composer.compose_string(self.description, 'utf-8', 4)
        composer.compose_string(self.language, 'ascii', 4)

        return composer.composed


@attr.s
class SshUnimplementedMessage(SshMessageBase):
    sequence_number = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.UNIMPLEMENTED

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('sequence_number', 4)

        return SshUnimplementedMessage(parser['sequence_number']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(self.sequence_number, 4)

        return composer.composed


@attr.s
class SshDHKeyExchangeInitBase(SshMessageBase):
    ephemeral_public_key = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    @abc.abstractmethod
    def get_message_code(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        body_parser = ParserBinary(parsable[header_parser.parsed_length:])
        body_parser.parse_bytes('ephemeral_public_key', 4)

        return cls(
            body_parser['ephemeral_public_key']
        ), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_bytes(self.ephemeral_public_key, 4)

        return composer.composed


class SshDHKeyExchangeInit(SshDHKeyExchangeInitBase):
    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DH_KEX_INIT


class SshDHGroupExchangeInit(SshDHKeyExchangeInitBase):
    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DH_GEX_INIT


@attr.s
class SshDHKeyExchangeReplyBase(SshMessageBase):
    host_public_key = attr.ib(validator=attr.validators.instance_of(SshPublicKeyBase))
    ephemeral_public_key = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    signature = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    @abc.abstractmethod
    def get_message_code(cls):
        raise NotImplementedError()

    @staticmethod
    def _parse_ssh_key(parser):
        parser.parse_parsable('host_public_key', SshHostPublicKeyVariant, 4)
        parser.parse_bytes('ephemeral_public_key', 4)
        parser.parse_bytes('signature', 4)

        return parser['host_public_key'], parser['ephemeral_public_key'], parser['signature']

    @staticmethod
    def _compose_ssh_key(composer, host_public_key, ephemeral_public_key_bytes, signature_bytes):
        composer.compose_parsable(host_public_key, 4)
        composer.compose_bytes(ephemeral_public_key_bytes, 4)
        composer.compose_bytes(signature_bytes, 4)

    @classmethod
    def _parse(cls, parsable):

        parser = cls._parse_header(parsable)

        host_public_key, ephemeral_public_key, signature = cls._parse_ssh_key(parser)

        return cls(
            host_public_key,
            ephemeral_public_key,
            signature,
        ), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        self._compose_ssh_key(composer, self.host_public_key, self.ephemeral_public_key, self.signature)

        return composer.composed


class SshDHKeyExchangeReply(SshDHKeyExchangeReplyBase):
    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DH_KEX_REPLY


class SshDHGroupExchangeReply(SshDHKeyExchangeReplyBase):
    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DH_GEX_REPLY


@attr.s
class SshDHGroupExchangeRequest(SshMessageBase):
    gex_min = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    gex_number = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    gex_max = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DH_GEX_REQUEST

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        body_parser = ParserBinary(parsable[header_parser.parsed_length:])
        body_parser.parse_numeric('gex_min', 4)
        body_parser.parse_numeric('gex_number', 4)
        body_parser.parse_numeric('gex_max', 4)

        return SshDHGroupExchangeRequest(
            body_parser['gex_min'],
            body_parser['gex_number'],
            body_parser['gex_max'],
        ), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(self.gex_min, 4)
        composer.compose_numeric(self.gex_number, 4)
        composer.compose_numeric(self.gex_max, 4)

        return composer.composed


@attr.s
class SshDHGroupExchangeGroup(SshMessageBase):
    p = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    g = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def get_message_code(cls):
        return SshMessageCode.DH_GEX_GROUP

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        body_parser = ParserBinary(parsable[header_parser.parsed_length:])
        body_parser.parse_bytes('p', 4)
        body_parser.parse_bytes('g', 4)

        return SshDHGroupExchangeGroup(
            body_parser['p'],
            body_parser['g'],
        ), header_parser.parsed_length + body_parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_bytes(self.p, 4)
        composer.compose_bytes(self.g, 4)

        return composer.composed


@attr.s
class SshNewKeys(SshMessageBase):
    @classmethod
    def get_message_code(cls):
        return SshMessageCode.NEWKEYS

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        return SshNewKeys(), header_parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        return composer.composed


class SshMessageVariantInit(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshMessageCode.DISCONNECT, (SshDisconnectMessage, )),
        (SshMessageCode.UNIMPLEMENTED, (SshUnimplementedMessage, )),
        (SshMessageCode.KEXINIT, (SshKeyExchangeInit, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS


class SshMessageVariantKexDH(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshMessageCode.DISCONNECT, (SshDisconnectMessage, )),
        (SshMessageCode.KEXINIT, (SshKeyExchangeInit, )),
        (SshMessageCode.UNIMPLEMENTED, (SshUnimplementedMessage, )),
        (SshMessageCode.DH_KEX_INIT, (SshDHKeyExchangeInit, )),
        (SshMessageCode.DH_KEX_REPLY, (SshDHKeyExchangeReply, )),
        (SshMessageCode.NEWKEYS, (SshNewKeys, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS


class SshMessageVariantKexDHGroup(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshMessageCode.DISCONNECT, (SshDisconnectMessage, )),
        (SshMessageCode.KEXINIT, (SshKeyExchangeInit, )),
        (SshMessageCode.UNIMPLEMENTED, (SshUnimplementedMessage, )),
        (SshMessageCode.DH_GEX_REQUEST, (SshDHGroupExchangeRequest, )),
        (SshMessageCode.DH_GEX_GROUP, (SshDHGroupExchangeGroup, )),
        (SshMessageCode.DH_GEX_INIT, (SshDHGroupExchangeInit, )),
        (SshMessageCode.DH_GEX_REPLY, (SshDHGroupExchangeReply, )),
        (SshMessageCode.NEWKEYS, (SshNewKeys, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
