#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import calendar
import datetime
import enum
import random

from cryptoparser.common.base import Opaque, Vector, VectorParamNumeric, VectorParamParsable, VectorParsable
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary

from cryptoparser.tls.extension import TlsExtensions
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionBase, TlsProtocolVersionFinal
from cryptoparser.tls.ciphersuite import TlsCipherSuiteFactory


class TlsContentType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


class TlsSubprotocolMessageBase(ParsableBase):
    @abc.abstractmethod
    def get_content_type(cls):
        raise NotImplementedError()


class TlsAlertLevel(enum.IntEnum):
    WARNING = 0x01
    FATAL = 0x02


class TlsAlertDescription(enum.IntEnum):
    CLOSE_NOTIFY = 0x00
    UNEXPECTED_MESSAGE = 0x0a
    BAD_RECORD_MAC = 0x14
    RECORD_OVERFLOW = 0x16
    HANDSHAKE_FAILURE = 0x28
    BAD_CERTIFICATE = 0x2a
    UNSUPPORTED_CERTIFICATE = 0x2b
    CERTIFICATE_REVOKED = 0x2c
    CERTIFICATE_EXPIRED = 0x2d
    CERTIFICATE_UNKNOWN = 0x2e
    ILLEGAL_PARAMETER = 0x2f
    UNKNOWN_CA = 0x30
    ACCESS_DENIED = 0x30
    DECODE_ERROR = 0x32
    DECRYPT_ERROR = 0x33
    PROTOCOL_VERSION = 0x46
    INSUFFICIENT_SECURITY = 0x47
    INTERNAL_ERROR = 0x50
    INAPPROPRIATE_FALLBACK = 0x56
    USER_CANCELED = 0x5a
    MISSING_EXTENSION = 0x6d
    UNSUPPORTED_EXTENSION = 0x6e
    CERTIFICATE_UNOBTAINABLE = 0x6f
    UNRECOGNIZED_NAME = 0x70
    BAD_CERTIFICATE_STATUS_RESPONSE = 0x71
    BAD_CERTIFICATE_HASH_VALUE = 0x72
    UNKNOWN_PSK_IDENTITY = 0x73
    CERTIFICATE_REQUIRED = 0x74
    NO_APPLICATION_PROTOCOL = 0x78


class TlsAlertMessage(TlsSubprotocolMessageBase):
    _SIZE = 2

    def __init__(self, level, description):
        self.level = level
        self.description = description

    @classmethod
    def get_content_type(cls):
        return TlsContentType.ALERT

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls._SIZE:
            raise NotEnoughData(cls._SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('level', 1)
        parser.parse_numeric('description', 1)

        return TlsAlertMessage(parser['level'], parser['description']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.level, 1)
        composer.compose_numeric(self.description, 1)

        return composer.composed_bytes

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, value):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._level = TlsAlertLevel(value)
        except ValueError:
            raise InvalidValue(value, TlsAlertLevel, 'level')

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._description = TlsAlertDescription(value)
        except ValueError:
            raise InvalidValue(value, TlsAlertDescription)

    def __eq__(self, other):
        return self.level == other.level and self.description == other.description


class TlsChangeCipherSpecType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x01


class TlsChangeCipherSpecMessage(TlsSubprotocolMessageBase):
    def __init__(self, change_cipher_spec_type=TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC):
        super(TlsChangeCipherSpecMessage, self).__init__()

        self._change_cipher_spec_type = change_cipher_spec_type

    @classmethod
    def get_content_type(cls):
        return TlsContentType.CHANGE_CIPHER_SPEC

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('change_cipher_spec_type', 1, TlsChangeCipherSpecType)

        return TlsChangeCipherSpecMessage(parser['change_cipher_spec_type']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self._change_cipher_spec_type, 1)

        return composer.composed_bytes

    def __eq__(self, other):
        return self._change_cipher_spec_type == other._change_cipher_spec_type  # pylint: disable=protected-access


class TlsApplicationDataMessage(TlsSubprotocolMessageBase):
    def __init__(self, data):
        super(TlsApplicationDataMessage, self).__init__()

        self.data = data

    @classmethod
    def get_content_type(cls):
        return TlsContentType.APPLICATION_DATA

    @classmethod
    def _parse(cls, parsable):
        return TlsApplicationDataMessage(parsable), len(parsable)

    def compose(self):
        return self.data

    def __eq__(self, other):
        return self.data == other.data


class TlsHandshakeType(enum.IntEnum):
    HELLO_REQUEST = 0x00
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    HELLO_VERIFY_REQUEST = 0x03
    NEW_SESSION_TICKET = 0x04
    CERTIFICATE = 0x0b
    SERVER_KEY_EXCHANGE = 0x0c
    CERTIFICATE_REQUEST = 0x0d
    SERVER_HELLO_DONE = 0x0e
    CERTIFICATE_VERIFY = 0x0f
    CLIENT_KEY_EXCHANGE = 0x10
    FINISHED = 0x14
    CLIENT_CERTIFICATE_URL = 0x15
    CERTIFICATE_STATUS = 0x16
    SUPPLEMENTAL_DATA = 0x17


class TlsHandshakeMessage(TlsSubprotocolMessageBase):
    """The payload of a handshake record.
    """
    _HEADER_SIZE = 4

    @classmethod
    def get_content_type(cls):
        return TlsContentType.HANDSHAKE

    @classmethod
    @abc.abstractmethod
    def get_handshake_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_handshake_header(cls, parsable):
        if len(parsable) < cls._HEADER_SIZE:
            raise NotEnoughData(cls._HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        try:
            parser.parse_numeric('handshake_type', 1, TlsHandshakeType)
        except InvalidValue as e:
            raise e
        else:
            if parser['handshake_type'] != cls.get_handshake_type():
                raise InvalidType()

        parser.parse_numeric('handshake_length', 3)

        try:
            parser.parse_bytes('payload', parser['handshake_length'])
        except NotEnoughData as e:
            raise NotEnoughData(e.bytes_needed)

        return parser

    def _compose_header(self, payload_length):
        composer = ComposerBinary()

        composer.compose_numeric(self.get_handshake_type(), 1)
        composer.compose_numeric(payload_length, 3)

        return composer.composed_bytes


class TlsHandshakeHelloRandomBytes(Opaque):
    @classmethod
    def get_byte_num(cls):
        return 28


class TlsHandshakeHelloRandom(ParsableBase):
    def __init__(
            self,
            time=datetime.datetime.now(),
            random_bytes=bytearray.fromhex('{:28x}'.format(random.getrandbits(224)).zfill(56))
    ):
        self._time = None
        self._random = None

        self.time = time
        self.random = random_bytes

    @property
    def random(self):
        return bytearray(self._random)

    @random.setter
    def random(self, value):
        self._random = TlsHandshakeHelloRandomBytes(value)

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value

    def __eq__(self, other):
        return self.time == other.time and self.random == other.random

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('time', 4, datetime.datetime.utcfromtimestamp)
        parser.parse_parsable('random', TlsHandshakeHelloRandomBytes)

        return TlsHandshakeHelloRandom(parser['time'], parser['random']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(int(calendar.timegm(self._time.utctimetuple())), 4)
        composer.compose_parsable(self._random)

        return composer.composed_bytes


class TlsHandshakeHello(TlsHandshakeMessage):
    def __init__(self, protocol_version, random_bytes, session_id, extensions):
        super(TlsHandshakeHello, self).__init__()

        self.protocol_version = protocol_version
        self.random = random_bytes
        self.session_id = session_id
        self.extensions = extensions

    @classmethod
    def _parse_hello_header(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_parsable('protocol_version', TlsProtocolVersionBase)
        parser.parse_parsable('random', TlsHandshakeHelloRandom)
        parser.parse_parsable('session_id', TlsSessionIdVector)

        return parser

    def _compose_header(self, payload_length):
        composer = ComposerBinary()

        handshake_header_bytes = super(TlsHandshakeHello, self)._compose_header(
            payload_length + composer.composed_length
        )

        return handshake_header_bytes + composer.composed_bytes

    @classmethod
    def _parse_extensions(cls, handshake_header_parser, parser):
        if parser.parsed_length >= handshake_header_parser['handshake_length']:
            return None

        parser.parse_parsable('extensions', TlsExtensions)

        return parser

    def _compose_extensions(self):
        extension_bytes = bytearray()

        for extension in self.extensions:
            extension_bytes += extension.compose()

        payload_composer = ComposerBinary()
        if self.extensions:
            payload_composer.compose_numeric(len(extension_bytes), 2)

        return payload_composer.composed_bytes + extension_bytes

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsCipherSuiteVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsCipherSuiteFactory,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 16 - 2
        )


class TlsCompressionMethod(enum.IntEnum):
    NULL = 0


class TlsCompressionMethodVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
            numeric_class=TlsCompressionMethod
        )


class TlsSessionIdVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=0, max_byte_num=32)


class TlsHandshakeClientHello(TlsHandshakeHello):
    def __init__(  # pylint: disable=too-many-arguments
            self,
            cipher_suites,
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            random_bytes=TlsHandshakeHelloRandom(),
            session_id=TlsSessionIdVector(()),
            compression_methods=TlsCompressionMethodVector([TlsCompressionMethod.NULL, ]),
            extensions=(),
    ):
        super(TlsHandshakeClientHello, self).__init__(protocol_version, random_bytes, session_id, extensions)

        self.cipher_suites = TlsCipherSuiteVector(cipher_suites)
        self.compression_methods = compression_methods

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.CLIENT_HELLO

    @classmethod
    def _parse(cls, parsable):

        handshake_header_parser = cls._parse_handshake_header(parsable)

        parser = cls._parse_hello_header(handshake_header_parser['payload'])
        parser.parse_parsable('cipher_suites', TlsCipherSuiteVector)
        parser.parse_parsable('compression_methods', TlsCompressionMethodVector)

        extension_parser = cls._parse_extensions(handshake_header_parser, parser)

        return TlsHandshakeClientHello(
            parser['cipher_suites'],
            parser['protocol_version'],
            parser['random'],
            parser['session_id'],
            parser['compression_methods'],
            extensions=parser['extensions'] if extension_parser else TlsExtensions([]),
        ), handshake_header_parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.protocol_version)
        payload_composer.compose_parsable(self.random)
        payload_composer.compose_parsable(self.session_id)
        payload_composer.compose_parsable(self.cipher_suites)
        payload_composer.compose_parsable(self.compression_methods)

        extension_bytes = self._compose_extensions()

        header_bytes = self._compose_header(payload_composer.composed_length + len(extension_bytes))

        return header_bytes + payload_composer.composed_bytes + extension_bytes


class TlsHandshakeServerHello(TlsHandshakeHello):
    def __init__(  # pylint: disable=too-many-arguments
            self,
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            random_bytes=TlsHandshakeHelloRandom(),
            session_id=TlsSessionIdVector((random.randint(0, 255) for i in range(32))),
            compression_method=TlsCompressionMethod.NULL,
            cipher_suite=None,
            extensions=None,
    ):
        super(TlsHandshakeServerHello, self).__init__(protocol_version, random_bytes, session_id, extensions)

        self.cipher_suite = cipher_suite
        self.compression_method = compression_method

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_HELLO

    @classmethod
    def _parse(cls, parsable):
        handshake_header_parser = cls._parse_handshake_header(parsable)

        parser = cls._parse_hello_header(handshake_header_parser['payload'])

        parser.parse_parsable('cipher_suite', TlsCipherSuiteFactory)
        parser.parse_numeric('compression_method', 1)

        extension_parser = cls._parse_extensions(handshake_header_parser, parser)

        return TlsHandshakeServerHello(
            protocol_version=parser['protocol_version'],
            random_bytes=parser['random'],
            session_id=parser['session_id'],
            compression_method=parser['compression_method'],
            cipher_suite=parser['cipher_suite'],
            extensions=parser['extensions'] if extension_parser else TlsExtensions([]),
        ), handshake_header_parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.protocol_version)
        payload_composer.compose_parsable(self.random)
        payload_composer.compose_parsable(self.session_id)
        payload_composer.compose_parsable(self.cipher_suite)
        payload_composer.compose_numeric(self.compression_method.value, 1)

        extension_bytes = self._compose_extensions()

        header_bytes = self._compose_header(payload_composer.composed_length + len(extension_bytes))

        return header_bytes + payload_composer.composed_bytes + extension_bytes


class TlsCertificate(ParsableBase):
    def __init__(self, certificate):
        self.certificate = certificate

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('certificate_length', 3)
        parser.parse_bytes('certificate', parser['certificate_length'])

        return TlsCertificate(parser['certificate']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(len(self.certificate), 3)
        composer.compose_bytes(self.certificate)

        return composer.composed_bytes

    def __eq__(self, other):
        return self.certificate == other.certificate


class TlsCertificates(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsCertificate,
            fallback_class=None,
            min_byte_num=1, max_byte_num=2 ** 24 - 1
        )


class TlsHandshakeCertificate(TlsHandshakeMessage):
    def __init__(self, certificate_chain):
        super(TlsHandshakeCertificate, self).__init__()

        self.certificate_chain = certificate_chain

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.CERTIFICATE

    @classmethod
    def _parse(cls, parsable):
        handshake_header_parser = cls._parse_handshake_header(parsable)

        parser = ParserBinary(handshake_header_parser['payload'])

        parser.parse_parsable('certificates', TlsCertificates)

        return TlsHandshakeCertificate(
            parser['certificates']
        ), handshake_header_parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()
        payload_composer.compose_parsable(self.certificate_chain)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsHandshakeServerHelloDone(TlsHandshakeMessage):
    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_HELLO_DONE

    @classmethod
    def _parse(cls, parsable):
        handshake_header_parser = cls._parse_handshake_header(parsable)

        if handshake_header_parser['handshake_length'] != 0:
            raise InvalidValue(handshake_header_parser['handshake_length'], TlsHandshakeServerHelloDone)

        return TlsHandshakeServerHelloDone(), handshake_header_parser.parsed_length

    def compose(self):
        return self._compose_header(0)


class TlsECCurveType(enum.IntEnum):
    EXPLICIT_PRIME = 1
    EXPLICIT_CHAR2 = 2
    NAMED_CURVE = 3


class TlsHandshakeServerKeyExchange(TlsHandshakeMessage):
    def __init__(self, param_bytes):
        super(TlsHandshakeServerKeyExchange, self).__init__()

        self.param_bytes = param_bytes

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_KEY_EXCHANGE

    @classmethod
    def _parse(cls, parsable):
        handshake_header_parser = cls._parse_handshake_header(parsable)

        return TlsHandshakeServerKeyExchange(
            handshake_header_parser['payload']
        ), handshake_header_parser.parsed_length

    def compose(self):
        return self._compose_header(len(self.param_bytes)) + self.param_bytes
