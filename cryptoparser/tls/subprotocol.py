# -*- coding: utf-8 -*-

import abc
import calendar
import collections
import datetime
import enum
import random
import attr

import six

from cryptoparser.common.base import (
    Opaque,
    VariantParsable,
    Vector,
    VectorParamNumeric,
    VectorParamParsable,
    VectorParsable,
)
from cryptoparser.common.exception import NotEnoughData, InvalidValue, InvalidType
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary

from cryptoparser.tls.extension import TlsExtensions, TlsExtensionType
from cryptoparser.tls.grease import TlsInvalidType, TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.version import (
    SslProtocolVersion,
    SslVersion,
    TlsProtocolVersionBase,
    TlsProtocolVersionFinal,
    TlsVersion,
)
from cryptoparser.tls.ciphersuite import (
    SslCipherKind,
    SslCipherKindFactory,
    TlsCipherSuite,
    TlsCipherSuiteExtension,
    TlsCipherSuiteFactory,
)


class TlsContentType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


@attr.s
class SubprotocolParser(object):
    _subprotocol_type = attr.ib(validator=attr.validators.instance_of(enum.IntEnum))

    @classmethod
    @abc.abstractmethod
    def _get_subprotocol_parsers(cls):
        raise NotImplementedError()

    @classmethod
    def register_subprotocol_parser(cls, subprotocol_type, parsable_class):
        subprotocol_parsers = cls._get_subprotocol_parsers()
        subprotocol_parsers[subprotocol_type] = parsable_class

    def parse(self, parsable):
        subprotocol_parsers = self._get_subprotocol_parsers()

        if self._subprotocol_type in subprotocol_parsers:
            parsed_object, parsed_length = subprotocol_parsers[self._subprotocol_type].parse_immutable(parsable)
            return parsed_object, parsed_length

        raise InvalidValue(self._subprotocol_type, TlsSubprotocolMessageBase)


class TlsSubprotocolMessageBase(ParsableBase):
    @classmethod
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


@attr.s
class TlsAlertMessage(TlsSubprotocolMessageBase):
    _SIZE = 2

    level = attr.ib()
    description = attr.ib()

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

    @level.validator
    def _validator_level(self, attribute, value):  # pylint: disable=unused-argument
        try:
            self.level = TlsAlertLevel(value)
        except ValueError as e:
            six.raise_from(InvalidValue(value, TlsAlertLevel, 'level'), e)

    @description.validator
    def _validator_description(self, attribute, value):  # pylint: disable=unused-argument
        try:
            self.description = TlsAlertDescription(value)
        except ValueError as e:
            six.raise_from(InvalidValue(value, TlsAlertDescription), e)


TlsSubprotocolMessageBase.register(TlsAlertMessage)


class TlsChangeCipherSpecType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x01


@attr.s
class TlsChangeCipherSpecMessage(TlsSubprotocolMessageBase):
    _change_cipher_spec_type = attr.ib(
        default=TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC,
        validator=attr.validators.in_(TlsChangeCipherSpecType)
    )

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


@attr.s
class TlsApplicationDataMessage(TlsSubprotocolMessageBase):
    data = attr.ib(attr.validators.instance_of(bytearray))

    @classmethod
    def get_content_type(cls):
        return TlsContentType.APPLICATION_DATA

    @classmethod
    def _parse(cls, parsable):
        return TlsApplicationDataMessage(parsable), len(parsable)

    def compose(self):
        return self.data


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


@attr.s
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
            six.raise_from(NotEnoughData(e.bytes_needed), e)

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


@attr.s
class TlsHandshakeHelloRandom(ParsableBase):
    time = attr.ib(validator=attr.validators.instance_of(datetime.datetime))
    random = attr.ib(validator=attr.validators.instance_of(TlsHandshakeHelloRandomBytes))

    @time.default
    def _default_time(self):  # pylint: disable=no-self-use
        return datetime.datetime.now()

    @random.default
    def _default_random(self):  # pylint: disable=no-self-use
        return TlsHandshakeHelloRandomBytes(
            bytearray.fromhex('{:28x}'.format(random.getrandbits(224)).zfill(56))
        )

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('time', 4, datetime.datetime.utcfromtimestamp)
        parser.parse_parsable('random', TlsHandshakeHelloRandomBytes)

        return TlsHandshakeHelloRandom(parser['time'], parser['random']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(int(calendar.timegm(self.time.utctimetuple())), 4)
        composer.compose_parsable(self.random)

        return composer.composed_bytes


@attr.s
class TlsHandshakeHello(TlsHandshakeMessage):
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

    @staticmethod
    def _compose_extensions(extensions):
        extension_bytes = bytearray()

        for extension in extensions:
            extension_bytes += extension.compose()

        payload_composer = ComposerBinary()
        if extensions:
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
            fallback_class=TlsInvalidTypeTwoByte,
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


@attr.s  # pylint: disable=too-many-instance-attributes
class TlsHandshakeClientHello(TlsHandshakeHello):
    cipher_suites = attr.ib(converter=TlsCipherSuiteVector)
    protocol_version = attr.ib(
        default=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        validator=attr.validators.instance_of((TlsProtocolVersionBase, SslProtocolVersion)),
    )
    random = attr.ib(
        default=TlsHandshakeHelloRandom(),
        validator=attr.validators.instance_of(TlsHandshakeHelloRandom),
    )
    session_id = attr.ib(
        default=TlsSessionIdVector(()),
        validator=attr.validators.instance_of(TlsSessionIdVector),
    )
    compression_methods = attr.ib(
        default=TlsCompressionMethodVector([TlsCompressionMethod.NULL, ]),
        validator=attr.validators.instance_of(TlsCompressionMethodVector),
    )
    extensions = attr.ib(default=TlsExtensions(()), validator=attr.validators.instance_of(TlsExtensions))
    fallback_scsv = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    empty_renegotiation_info_scsv = attr.ib(default=True, validator=attr.validators.instance_of(bool))

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

        cipher_suites = []
        fallback_scsv = False
        empty_renegotiation_info_scsv = False
        for cipher_suite in parser['cipher_suites']:
            if cipher_suite.value.code == TlsCipherSuiteExtension.FALLBACK_SCSV:
                fallback_scsv = True
            elif cipher_suite.value.code == TlsCipherSuiteExtension.EMPTY_RENEGOTIATION_INFO_SCSV:
                empty_renegotiation_info_scsv = True
            else:
                cipher_suites.append(cipher_suite)

        return TlsHandshakeClientHello(
            cipher_suites,
            parser['protocol_version'],
            parser['random'],
            parser['session_id'],
            parser['compression_methods'],
            extensions=parser['extensions'] if extension_parser else TlsExtensions([]),
            fallback_scsv=fallback_scsv,
            empty_renegotiation_info_scsv=empty_renegotiation_info_scsv,
        ), handshake_header_parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.protocol_version)
        payload_composer.compose_parsable(self.random)
        payload_composer.compose_parsable(self.session_id)
        if self.fallback_scsv:
            self.cipher_suites.append(TlsInvalidTypeTwoByte(TlsCipherSuiteExtension.FALLBACK_SCSV))
        if self.empty_renegotiation_info_scsv:
            self.cipher_suites.append(TlsInvalidTypeTwoByte(TlsCipherSuiteExtension.EMPTY_RENEGOTIATION_INFO_SCSV))
        payload_composer.compose_parsable(self.cipher_suites)
        if self.fallback_scsv:
            del self.cipher_suites[-1]
        if self.empty_renegotiation_info_scsv:
            del self.cipher_suites[-1]
        payload_composer.compose_parsable(self.compression_methods)

        extension_bytes = self._compose_extensions(self.extensions)

        header_bytes = self._compose_header(payload_composer.composed_length + len(extension_bytes))

        return header_bytes + payload_composer.composed_bytes + extension_bytes

    def ja3(self):
        parser = ParserBinary(self.protocol_version.compose())
        parser.parse_numeric('tls_protocol_version', 2)

        cipher_suites = [str(cipher_suite.value.code) for cipher_suite in self.cipher_suites]

        extension_types = []
        named_curves = []
        ec_point_formats = []
        for extension in self.extensions:
            if (not isinstance(extension.extension_type, TlsInvalidTypeTwoByte) or
                    extension.extension_type.value.value_type != TlsInvalidType.GREASE):
                extension_types.append(str(extension.extension_type.value.code))

            if extension.extension_type == TlsExtensionType.SUPPORTED_GROUPS:
                named_curves = [
                    str(named_curve.value.code)
                    for named_curve in extension.elliptic_curves
                    if (not isinstance(named_curve, TlsInvalidTypeTwoByte) or
                        named_curve.value.value_type != TlsInvalidType.GREASE)
                ]
            elif extension.extension_type == TlsExtensionType.EC_POINT_FORMATS:
                ec_point_formats = [
                    str(point_format.value.code)
                    for point_format in extension.point_formats
                    if (not isinstance(point_format, TlsInvalidTypeOneByte) or
                        point_format.value.value_type != TlsInvalidType.GREASE)
                ]

        return ','.join([
            str(parser['tls_protocol_version']),
            '-'.join(cipher_suites),
            '-'.join(extension_types),
            '-'.join(named_curves),
            '-'.join(ec_point_formats),
        ])


@attr.s
class TlsHandshakeServerHello(TlsHandshakeHello):
    protocol_version = attr.ib(
        default=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        validator=attr.validators.instance_of((TlsProtocolVersionBase, SslProtocolVersion)),
    )
    random = attr.ib(
        default=TlsHandshakeHelloRandom(),
        validator=attr.validators.instance_of(TlsHandshakeHelloRandom),
    )
    session_id = attr.ib(
        default=TlsSessionIdVector((random.randint(0, 255) for i in range(32))),
        validator=attr.validators.instance_of(TlsSessionIdVector),
    )
    compression_method = attr.ib(
        default=TlsCompressionMethod.NULL,
        validator=attr.validators.in_(TlsCompressionMethod),
    )
    cipher_suite = attr.ib(default=None, validator=attr.validators.in_(TlsCipherSuite))
    extensions = attr.ib(default=None, validator=attr.validators.instance_of(TlsExtensions))

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_HELLO

    @classmethod
    def _parse(cls, parsable):
        handshake_header_parser = cls._parse_handshake_header(parsable)

        parser = cls._parse_hello_header(handshake_header_parser['payload'])

        parser.parse_parsable('cipher_suite', TlsCipherSuiteFactory)
        parser.parse_numeric('compression_method', 1, TlsCompressionMethod)

        extension_parser = cls._parse_extensions(handshake_header_parser, parser)

        return TlsHandshakeServerHello(
            protocol_version=parser['protocol_version'],
            random=parser['random'],
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

        extension_bytes = self._compose_extensions(self.extensions)

        header_bytes = self._compose_header(payload_composer.composed_length + len(extension_bytes))

        return header_bytes + payload_composer.composed_bytes + extension_bytes


@attr.s
class TlsCertificate(ParsableBase):
    certificate = attr.ib(validator=attr.validators.instance_of(bytes))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('certificate_length', 3)
        parser.parse_bytes('certificate', parser['certificate_length'])

        return TlsCertificate(bytes(parser['certificate'])), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(len(self.certificate), 3)
        composer.compose_bytes(self.certificate)

        return composer.composed_bytes


class TlsCertificates(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsCertificate,
            fallback_class=None,
            min_byte_num=1, max_byte_num=2 ** 24 - 1
        )


@attr.s
class TlsHandshakeCertificate(TlsHandshakeMessage):
    certificate_chain = attr.ib(validator=attr.validators.instance_of(TlsCertificates))

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


@attr.s
class TlsHandshakeServerKeyExchange(TlsHandshakeMessage):
    param_bytes = attr.ib(validator=attr.validators.instance_of(bytes))

    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_KEY_EXCHANGE

    @classmethod
    def _parse(cls, parsable):
        handshake_header_parser = cls._parse_handshake_header(parsable)

        return TlsHandshakeServerKeyExchange(
            bytes(handshake_header_parser['payload'])
        ), handshake_header_parser.parsed_length

    def compose(self):
        return self._compose_header(len(self.param_bytes)) + bytes(self.param_bytes)


class SslMessageBase(ParsableBase):
    @classmethod
    def get_message_type(cls):
        return NotImplementedError()  # pragma: no cover

    # pylint: disable=duplicate-code
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    # pylint: disable=duplicate-code
    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class SslMessageType(enum.IntEnum):
    ERROR = 0x00
    CLIENT_HELLO = 0x01
    CLIENT_MASTER_KEY = 0x02
    CLIENT_FINISHED = 0x03
    SERVER_HELLO = 0x04
    SERVER_VERIFY = 0x05
    SERVER_FINISHED = 0x06
    REQUEST_CERTIFICATE = 0x07
    CLIENT_CERTIFICATE = 0x08


class SslCertificateType(enum.IntEnum):
    X509_CERTIFICATE = 0x01


class SslAuthenticationType(enum.IntEnum):
    MD5_WITH_RSA_ENCRYPTION = 0x01


class SslErrorType(enum.IntEnum):
    NO_CIPHER_ERROR = 0x0001
    NO_CERTIFICATE_ERROR = 0x0002
    BAD_CERTIFICATE_ERROR = 0x0003
    UNSUPPORTED_CERTIFICATE_TYPE_ERROR = 0x0004


@attr.s
class SslErrorMessage(SslMessageBase):
    error_type = attr.ib(validator=attr.validators.in_(SslErrorType))

    @classmethod
    def get_message_type(cls):
        return SslMessageType.ERROR

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('error_type', 2, SslErrorType)

        return SslErrorMessage(parser['error_type']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.error_type, 2)

        return composer.composed_bytes


@attr.s
class SslHandshakeClientHello(SslMessageBase):
    cipher_kinds = attr.ib(validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SslCipherKind)))
    session_id = attr.ib(validator=attr.validators.instance_of(bytes))
    challenge = attr.ib(validator=attr.validators.instance_of(bytes))

    @session_id.default
    def _default_session_id(self):  # pylint: disable=no-self-use
        return bytes()

    @challenge.default
    def _default_challenge(self):  # pylint: disable=no-self-use
        return bytes(bytearray.fromhex('{:16x}'.format(random.getrandbits(128)).zfill(32)))

    @classmethod
    def get_message_type(cls):
        return SslMessageType.CLIENT_HELLO

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('version', 2, SslVersion)
        parser.parse_numeric('cipher_kinds_length', 2)
        parser.parse_numeric('session_id_length', 2)
        parser.parse_numeric('challenge_length', 2)
        parser.parse_parsable_array('cipher_kinds', parser['cipher_kinds_length'], SslCipherKindFactory)
        parser.parse_bytes('session_id', parser['session_id_length'])
        parser.parse_bytes('challenge', parser['challenge_length'])

        return SslHandshakeClientHello(
            cipher_kinds=parser['cipher_kinds'],
            session_id=bytes(parser['session_id']),
            challenge=bytes(parser['challenge']),
        ), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(SslVersion.SSL2, 2)

        composer.compose_numeric(len(self.cipher_kinds) * 3, 2)
        composer.compose_numeric(len(self.session_id), 2)
        composer.compose_numeric(len(self.challenge), 2)

        composer.compose_parsable_array(self.cipher_kinds)
        composer.compose_bytes(self.session_id)
        composer.compose_bytes(self.challenge)

        return composer.composed_bytes


@attr.s
class SslHandshakeServerHello(SslMessageBase):
    certificate = attr.ib(validator=attr.validators.instance_of(bytes))
    cipher_kinds = attr.ib(validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SslCipherKind)))
    connection_id = attr.ib(validator=attr.validators.instance_of(bytes))
    session_id_hit = attr.ib(default=False, validator=attr.validators.instance_of(bool))

    @connection_id.default
    def _default_connection_id(self):  # pylint: disable=no-self-use
        return bytes()

    @classmethod
    def get_message_type(cls):
        return SslMessageType.SERVER_HELLO

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('session_id_hit', 1)
        parser.parse_numeric('certificate_type', 1, SslCertificateType)
        parser.parse_numeric('version', 2, SslVersion)
        parser.parse_numeric('certificate_length', 2)
        parser.parse_numeric('cipher_kinds_length', 2)
        parser.parse_numeric('connection_id_length', 2)
        parser.parse_bytes('certificate', parser['certificate_length'])
        parser.parse_parsable_array('cipher_kinds', parser['cipher_kinds_length'], SslCipherKindFactory)
        parser.parse_bytes('connection_id', parser['connection_id_length'])

        return SslHandshakeServerHello(
            certificate=bytes(parser['certificate']),
            cipher_kinds=parser['cipher_kinds'],
            connection_id=bytes(parser['connection_id']),
            session_id_hit=bool(parser['session_id_hit']),
        ), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(1 if self.session_id_hit else 0, 1)
        composer.compose_numeric(SslCertificateType.X509_CERTIFICATE, 1)
        composer.compose_numeric(SslVersion.SSL2, 2)
        composer.compose_numeric(len(self.certificate), 2)
        composer.compose_numeric(len(self.cipher_kinds) * 3, 2)
        composer.compose_numeric(len(self.connection_id), 2)
        composer.compose_bytes(self.certificate)
        composer.compose_parsable_array(self.cipher_kinds)
        composer.compose_bytes(self.connection_id)

        return composer.composed_bytes


class TlsHandshakeMessageVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (TlsHandshakeType.CLIENT_HELLO, [TlsHandshakeClientHello, ]),
        (TlsHandshakeType.SERVER_HELLO, [TlsHandshakeServerHello, ]),
        (TlsHandshakeType.CERTIFICATE, [TlsHandshakeCertificate, ]),
        (TlsHandshakeType.SERVER_KEY_EXCHANGE, [TlsHandshakeServerKeyExchange, ]),
        (TlsHandshakeType.SERVER_HELLO_DONE, [TlsHandshakeServerHelloDone, ]),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS


class TlsSubprotocolMessageParser(SubprotocolParser):
    _SUBPROTOCOL_PARSERS = {
        TlsContentType.CHANGE_CIPHER_SPEC: TlsChangeCipherSpecMessage,
        TlsContentType.ALERT: TlsAlertMessage,
        TlsContentType.HANDSHAKE: TlsHandshakeMessageVariant,
        TlsContentType.APPLICATION_DATA: TlsApplicationDataMessage,
    }

    @classmethod
    def _get_subprotocol_parsers(cls):
        return cls._SUBPROTOCOL_PARSERS


class SslSubprotocolMessageParser(SubprotocolParser):
    _SUBPROTOCOL_PARSERS = {
        SslMessageType.ERROR: SslErrorMessage,
        SslMessageType.CLIENT_HELLO: SslHandshakeClientHello,
        SslMessageType.SERVER_HELLO: SslHandshakeServerHello,
    }

    @classmethod
    def _get_subprotocol_parsers(cls):
        return cls._SUBPROTOCOL_PARSERS
