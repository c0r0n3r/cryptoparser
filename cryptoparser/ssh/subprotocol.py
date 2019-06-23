#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import collections
import enum
import random
import six

import attr

from cryptoparser.common.base import VectorString, VectorParamString
from cryptoparser.common.classes import LanguageTag
from cryptoparser.common.exception import InvalidValue, InvalidType, TooMuchData
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ParserText, ComposerText

from cryptoparser.tls.subprotocol import VariantParsable

from cryptoparser.ssh.ciphersuite import (
    SshKexAlgorithm,
    SshHostKeyAlgorithm,
    SshEncryptionAlgorithm,
    SshMacAlgorithm,
    SshCompressionAlgorithm,
)

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
    software_version = attr.ib(validator=attr.validators.instance_of(six.string_types))
    comment = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)), default=None)

    @software_version.validator
    def software_version_validator(self, _, value):  # pylint: disable=no-self-use
        if '\r' in value or '\n' in value or ' ' in value:
            raise InvalidValue(value, SshProtocolMessage, 'software_version')
        try:
            value.encode('ascii')
        except UnicodeEncodeError as e:
            six.raise_from(InvalidValue(value, SshProtocolMessage, 'software_version'), e)

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

        software_version = software_version_and_comment[0]
        if len(software_version_and_comment) > 1:
            comment = ' '.join(software_version_and_comment[1:])
        else:
            comment = None
        parser.parse_separator('\n')

        if parser.parsed_length > 255:
            raise TooMuchData(parser.parsed_length - 255)

        return SshProtocolMessage(parser['protocol_version'], software_version, comment), parser.parsed_length

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


class SshHandshakeMessageVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshMessageCode.DISCONNECT, (SshDisconnectMessage, )),
        (SshMessageCode.KEXINIT, (SshKeyExchangeInit, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
