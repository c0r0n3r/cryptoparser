#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import collections

from cryptoparser.common.base import Vector, VectorParsable, VectorParsableDerived
from cryptoparser.common.base import VectorParamNumeric, VectorParamParsable
from cryptoparser.common.algorithm import Authentication, MAC
from cryptoparser.common.base import TwoByteEnumComposer, TwoByteEnumParsable
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.tls.version import TlsProtocolVersionBase


class TlsExtensionType(enum.IntEnum):
    SERVER_NAME = 0x0000                             # [RFC6066]
    MAX_FRAGMENT_LENGTH = 0x0001                     # [RFC6066]
    CLIENT_CERTIFICATE_URL = 0x0002                  # [RFC6066]
    TRUSTED_CA_KEYS = 0x0003                         # [RFC6066]
    TRUNCATED_HMAC = 0x0004                          # [RFC6066]
    STATUS_REQUEST = 0x0005                          # [RFC6066]
    USER_MAPPING = 0x0006                            # [RFC4681]
    CLIENT_AUTHZ = 0x0007                            # [RFC5878]
    SERVER_AUTHZ = 0x0008                            # [RFC5878]
    CERT_TYPE = 0x0009                               # [RFC6091]
    SUPPORTED_GROUPS = 0x000a                        # [RFC-IETF-TLS-RFC]
    EC_POINT_FORMATS = 0x000b                        # [RFC-IETF-TLS-RFC]
    SRP = 0x000c                                     # [RFC5054]
    SIGNATURE_ALGORITHMS = 0x000d                    # [RFC5246]
    USE_SRTP = 0x000e                                # [RFC5764]
    HEARTBEAT = 0x000f                               # [RFC6520]
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010  # [RFC7301]
    STATUS_REQUEST_V = 0x0011                        # [RFC6961]
    SIGNED_CERTIFICATE_TIMESTAMP = 0x0012            # [RFC6962]
    CLIENT_CERTIFICATE_TYPE = 0x0013                 # [RFC7250]
    SERVER_CERTIFICATE_TYPE = 0x0014                 # [RFC7250]
    PADDING = 0x0015                                 # [RFC7685]
    ENCRYPT_THEN_MAC = 0x0016                        # [RFC7366]
    EXTENDED_MASTER_SECRET = 0x0017                  # [RFC7627]
    TOKEN_BINDING = 0x0018                           # [DRAFT-IETF-TOKBIND-NEGOTIATION]
    CACHED_INFO = 0x0019                             # [RFC7924]
    CERTIFICATE_COMPERSSION = 0x001b                 # [DRAFT-IETF-TLS-CERTIFICATE-COMPRESSION-04]
    RECORD_SIZE_LIMIT = 0X001C                       # [RFC8849]
    PWD_PROTECT = 0X001D                             # [RFC-HARKINS-TLS-DRAGONFLY-03]
    PWD_CLEAR = 0X001E                               # [RFC-HARKINS-TLS-DRAGONFLY-03]
    PASSWORD_SALT = 0X001F                           # [RFC-HARKINS-TLS-DRAGONFLY-03]
    SESSION_TICKET = 0X0023                          # [RFC4507]
    KEY_SHARE_RESERVED = 0X0028                      # [DRAFT-IETF-TLS-TLS13-20]
    PRE_SHARED_KEY = 0X0029                          # [DRAFT-IETF-TLS-TLS13-20]
    EARLY_DATA = 0X002A                              # [DRAFT-IETF-TLS-TLS13-20]
    SUPPORTED_VERSIONS = 0X002B                      # [DRAFT-IETF-TLS-TLS13-20]
    COOKIE = 0X002C                                  # [DRAFT-IETF-TLS-TLS13-20]
    PSK_KEY_EXCHANGE_MODES = 0X002D                  # [DRAFT-IETF-TLS-TLS13-20]
    CERTIFICATE_AUTHORITIES = 0X002F                 # [DRAFT-IETF-TLS-TLS13-20]
    OID_FILTERS = 0X0030                             # [DRAFT-IETF-TLS-TLS13-20]
    POST_HANDSHAKE_AUTH = 0x0031                     # [DRAFT-IETF-TLS-TLS13-20]
    SIGNATURE_ALGORITHMS_CERT = 0x0032               # [DRAFT-IETF-TLS-TLS13-23]
    KEY_SHARE = 0x0033                               # [DRAFT-IETF-TLS-TLS13-23]
    NEXT_PROTOCOL_NEGOTIATION = 0x3374               # [DRAFT-AGL-TLS-NEXTPROTONEG-04]
    CHANNEL_ID = 0x7550                              # [DRAFT-BALFANZ-TLS-OBC-01]
    RENEGOTIATION_INFO = 0xff01                      # [RFC5746]
    RECORD_HEADER = 0xff03                           # [DRAFT-FOSSATI-TLS-EXT-HEADER]


class TlsExtensions(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsExtensionParsed,
            fallback_class=TlsExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionBase(ParsableBase):
    def __init__(self, extension_type):
        self._extension_type = extension_type

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('extension_type', 2, TlsExtensionType)
        parser.parse_numeric('extension_length', 2)

        if parser.unparsed_length < parser['extension_length']:
            raise NotEnoughData(parser['extension_length'] + parser.parsed_length)

        return parser

    def _compose_header(self, payload_length):
        header_composer = ComposerBinary()

        header_composer.compose_numeric(self._extension_type, 2)
        header_composer.compose_numeric(payload_length, 2)

        return header_composer.composed_bytes


class TlsExtensionUnparsed(TlsExtensionBase):
    def __init__(self, extension_type, extension_data):
        super(TlsExtensionUnparsed, self).__init__(extension_type)

        self._extension_data = extension_data

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionUnparsed, cls)._parse_header(parsable)

        parser.parse_bytes('extension_data', parser['extension_length'])

        return TlsExtensionUnparsed(parser['extension_type'], parser['extension_data']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()
        payload_composer.compose_bytes(self._extension_data)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionParsed(TlsExtensionBase):
    def __init__(self):
        super(TlsExtensionParsed, self).__init__(self.get_extension_type())

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = super(TlsExtensionParsed, cls)._parse_header(parsable)

        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidValue(parser['extension_type'], TlsExtensionParsed, 'extension type')

        return parser


class TlsServerNameType(OneByteEnumComposer, enum.IntEnum):
    HOST_NAME = 0x00


class TlsServerName(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
        )


class TlsExtensionServerName(TlsExtensionParsed):
    def __init__(self, host_name, name_type=TlsServerNameType.HOST_NAME):
        super(TlsExtensionServerName, self).__init__()

        self.host_name = host_name
        self.name_type = name_type

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SERVER_NAME

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionServerName, cls)._parse_header(parsable)

        if parser['extension_length'] > 0:
            parser.parse_numeric('server_name_list_length', 2)
            parser.parse_numeric('server_name_type', 1, TlsServerNameType)
            parser.parse_parsable('server_name', TlsServerName)

            return TlsExtensionServerName(bytearray(parser['server_name']).decode('idna')), parser.parsed_length

        return TlsExtensionServerName(bytearray().decode('idna')), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        if self.host_name:
            idna_encoded_host_name = self.host_name.encode('idna')

            composer.compose_numeric(3 + len(idna_encoded_host_name), 2)
            composer.compose_numeric(self.name_type, 1)

            composer.compose_numeric(len(idna_encoded_host_name), 2)
            composer.compose_bytes(idna_encoded_host_name)

        header_bytes = self._compose_header(composer.composed_length)

        return header_bytes + composer.composed_bytes


class TlsECPointFormat(OneByteEnumComposer, enum.IntEnum):
    UNCOMPRESSED = 0x0
    ANSIX962_COMPRESSED_PRIME = 0x1
    ANSIX962_COMPRESSED_CHAR2 = 0x2


class TlsECPointFormatVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
            numeric_class=TlsECPointFormat
        )


class TlsExtensionECPointFormats(TlsExtensionParsed):
    def __init__(self, point_formats):
        super(TlsExtensionECPointFormats, self).__init__()

        self.point_formats = TlsECPointFormatVector(point_formats)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.EC_POINT_FORMATS

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionECPointFormats, cls)._parse_header(parsable)

        parser.parse_parsable('point_formats', TlsECPointFormatVector)

        return TlsExtensionECPointFormats(parser['point_formats']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.point_formats)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsNamedCurve(enum.IntEnum):
    SECT163K1 = 0x0001
    SECT163R1 = 0x0002
    SECT163R2 = 0x0003
    SECT193R1 = 0x0004
    SECT193R2 = 0x0005
    SECT233K1 = 0x0006
    SECT233R1 = 0x0007
    SECT239K1 = 0x0008
    SECT283K1 = 0x0009
    SECT283R1 = 0x000a
    SECT409K1 = 0x000b
    SECT409R1 = 0x000c
    SECT571K1 = 0x000d
    SECT571R1 = 0x000e
    SECP160K1 = 0x000f
    SECP160R1 = 0x0010
    SECP160R2 = 0x0011
    SECP192K1 = 0x0012
    SECP192R1 = 0x0013
    SECP224K1 = 0x0014
    SECP224R1 = 0x0015
    SECP256K1 = 0x0016
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019

    BRAINPOOLP256R1 = 0x001a
    BRAINPOOLP384R1 = 0x001b
    BRAINPOOLP512R1 = 0x001c
    X25519 = 0x001d
    X448 = 0x001e

    FFDHE2048 = 0x0100
    FFDHE3072 = 0x0101
    FFDHE4096 = 0x0102
    FFDHE6144 = 0x0103
    FFDHE8192 = 0x0104

    ARBITRARY_EXPLICIT_PRIME_CURVES = 0xff01
    ARBITRARY_EXPLICIT_CHAR2_CURVES = 0xff02


class TlsEllipticCurveVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=2,
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
            numeric_class=TlsNamedCurve
        )


class TlsExtensionEllipticCurves(TlsExtensionParsed):
    def __init__(self, elliptic_curves):
        super(TlsExtensionEllipticCurves, self).__init__()

        self.elliptic_curves = TlsEllipticCurveVector(elliptic_curves)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SUPPORTED_GROUPS

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionEllipticCurves, cls)._parse_header(parsable)

        parser.parse_parsable('elliptic_curves', TlsEllipticCurveVector)

        return TlsExtensionEllipticCurves(parser['elliptic_curves']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.elliptic_curves)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsSupportedVersionVector(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsProtocolVersionBase,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 8 - 2
        )


class TlsExtensionSupportedVersions(TlsExtensionParsed):
    def __init__(self, supported_versions):
        super(TlsExtensionSupportedVersions, self).__init__()

        self.supported_versions = TlsSupportedVersionVector(supported_versions)

    def __eq__(self, other):
        return self.supported_versions == other.supported_versions

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SUPPORTED_VERSIONS

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSupportedVersions, cls)._parse_header(parsable)

        parser.parse_parsable('supported_versions', TlsSupportedVersionVector)

        return TlsExtensionSupportedVersions(parser['supported_versions']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.supported_versions)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsSignatureAndHashAlgorithmFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsSignatureAndHashAlgorithm

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


HashAndSignatureAlgorithmParam = collections.namedtuple(
    'HashAndSignatureAlgorithmParam',
    ['code', 'hash_algorithm', 'signature_algorithm']
)


class TlsSignatureAndHashAlgorithm(TwoByteEnumComposer, enum.Enum):
    ANONYMOUS_NONE = HashAndSignatureAlgorithmParam(
        code=0x0000,
        signature_algorithm=Authentication.anon,
        hash_algorithm=None,
    )
    ANONYMOUS_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0100,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.MD5
    )
    ANONYMOUS_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0200,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA
    )
    ANONYMOUS_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0300,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA224
    )
    ANONYMOUS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0400,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA256
    )
    ANONYMOUS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0500,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA384
    )
    ANONYMOUS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0006,
        signature_algorithm=Authentication.anon,
        hash_algorithm=MAC.SHA512
    )
    RSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0001,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=None,
    )
    RSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0101,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.MD5
    )
    RSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0201,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA
    )
    RSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0301,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA224
    )
    RSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0401,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA256
    )
    RSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0501,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA384
    )
    RSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0601,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA512
    )
    DSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0002,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=None,
    )
    DSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0102,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.MD5
    )
    DSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0202,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA
    )
    DSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0302,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA224
    )
    DSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0402,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA256
    )
    DSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0502,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA384
    )
    DSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0602,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=MAC.SHA512
    )
    ECDSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0003,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=None,
    )
    ECDSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0103,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.MD5
    )
    ECDSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0203,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA
    )
    ECDSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0303,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA224
    )
    ECDSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0403,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA256
    )
    ECDSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0503,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA384
    )
    ECDSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0603,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=MAC.SHA512
    )


class TlsSignatureAndHashAlgorithmVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsSignatureAndHashAlgorithmFactory,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 16 - 2
        )


class TlsExtensionSignatureAlgorithms(TlsExtensionParsed):
    def __init__(self, hash_and_signature_algorithms):
        super(TlsExtensionSignatureAlgorithms, self).__init__()

        self.hash_and_signature_algorithms = TlsSignatureAndHashAlgorithmVector(hash_and_signature_algorithms)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SIGNATURE_ALGORITHMS

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSignatureAlgorithms, cls)._parse_header(parsable)

        parser.parse_parsable('hash_and_signature_algorithms', TlsSignatureAndHashAlgorithmVector)

        return TlsExtensionSignatureAlgorithms(parser['hash_and_signature_algorithms']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.hash_and_signature_algorithms)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes
