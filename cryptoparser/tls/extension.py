#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum
import collections

from cryptoparser.common.base import Opaque, OpaqueParam, Vector, VectorParsable, VectorParsableDerived, VariantParsable
from cryptoparser.common.base import VectorParamNumeric, VectorParamParsable
from cryptoparser.common.algorithm import Authentication, MAC, NamedGroup
from cryptoparser.common.base import OpaqueEnumParsable, OpaqueEnumComposer, TwoByteEnumComposer, TwoByteEnumParsable
from cryptoparser.common.base import OneByteEnumComposer, OneByteEnumParsable
from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.tls.version import TlsProtocolVersionBase


TlsNamedCurveParams = collections.namedtuple('TlsNamedCurveParams', ['code', 'named_group', ])
TlsProtocolNameParams = collections.namedtuple('TlsNamedCurveParams', ['code', ])


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
    RECORD_SIZE_LIMIT = 0x001c                       # [RFC8849]
    PWD_PROTECT = 0x001d                             # [RFC-HARKINS-TLS-DRAGONFLY-03]
    PWD_CLEAR = 0x001e                               # [RFC-HARKINS-TLS-DRAGONFLY-03]
    PASSWORD_SALT = 0x001f                           # [RFC-HARKINS-TLS-DRAGONFLY-03]
    SESSION_TICKET = 0x0023                          # [RFC4507]
    KEY_SHARE_RESERVED = 0x0028                      # [DRAFT-IETF-TLS-TLS13-20]
    PRE_SHARED_KEY = 0x0029                          # [DRAFT-IETF-TLS-TLS13-20]
    EARLY_DATA = 0x002a                              # [DRAFT-IETF-TLS-TLS13-20]
    SUPPORTED_VERSIONS = 0x002b                      # [DRAFT-IETF-TLS-TLS13-20]
    COOKIE = 0x002c                                  # [DRAFT-IETF-TLS-TLS13-20]
    PSK_KEY_EXCHANGE_MODES = 0x002d                  # [DRAFT-IETF-TLS-TLS13-20]
    CERTIFICATE_AUTHORITIES = 0x002f                 # [DRAFT-IETF-TLS-TLS13-20]
    OID_FILTERS = 0x0030                             # [DRAFT-IETF-TLS-TLS13-20]
    POST_HANDSHAKE_AUTH = 0x0031                     # [DRAFT-IETF-TLS-TLS13-20]
    SIGNATURE_ALGORITHMS_CERT = 0x0032               # [DRAFT-IETF-TLS-TLS13-23]
    KEY_SHARE = 0x0033                               # [DRAFT-IETF-TLS-TLS13-23]
    NEXT_PROTOCOL_NEGOTIATION = 0x3374               # [DRAFT-AGL-TLS-NEXTPROTONEG-04]
    CHANNEL_ID = 0x7550                              # [DRAFT-BALFANZ-TLS-OBC-01]
    RENEGOTIATION_INFO = 0xff01                      # [RFC5746]
    RECORD_HEADER = 0xff03                           # [DRAFT-FOSSATI-TLS-EXT-HEADER]
    GREASE_0A0A = 0x0a0a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_1A1A = 0x1a1a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_2A2A = 0x2a2a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_3A3A = 0x3a3a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_4A4A = 0x4a4a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_5A5A = 0x5a5a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_6A6A = 0x6a6a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_7A7A = 0x7a7a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_8A8A = 0x8a8a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_9A9A = 0x9a9a                             # [DRAFT-IETF-TLS-GREASE-01]
    GREASE_AAAA = 0xaaaa                             # [DRAFT-IETF-TLS-GREASE-01]


class TlsExtensions(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsExtensionVariant,
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


class TlsExtensionUnusedData(TlsExtensionBase):
    def __init__(self, extension_type, extension_data):
        super(TlsExtensionUnusedData, self).__init__(extension_type)

        self.extension_data = extension_data

    @classmethod
    def _parse_header_and_data(cls, parsable):
        parser = super(TlsExtensionUnusedData, cls)._parse_header(parsable)

        parser.parse_bytes('extension_data', parser['extension_length'])

        return parser

    def compose(self):
        payload_composer = ComposerBinary()
        payload_composer.compose_bytes(self.extension_data)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes

    def get_extension_type(self):
        return self._extension_type

    
class TlsExtensionUnparsed(TlsExtensionUnusedData):
    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header_and_data(parsable)

        return TlsExtensionUnparsed(parser['extension_type'], parser['extension_data']), parser.parsed_length


class TlsExtensionParsed(TlsExtensionBase):
    def __init__(self, extension_type=None):
        if extension_type is None:
            extension_type = self.get_extension_type()

        super(TlsExtensionParsed, self).__init__(extension_type)

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = super(TlsExtensionParsed, cls)._parse_header(parsable)

        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidType()

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


class TlsNamedCurveFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsNamedCurve

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsNamedCurve(TwoByteEnumComposer, enum.Enum):
    SECT163K1 = TlsNamedCurveParams(
        code=0x0001,
        named_group=NamedGroup.SECT163K1,
    )
    SECT163R1 = TlsNamedCurveParams(
        code=0x0002,
        named_group=NamedGroup.SECT163R1,
    )
    SECT163R2 = TlsNamedCurveParams(
        code=0x0003,
        named_group=NamedGroup.SECT163R2,
    )
    SECT193R1 = TlsNamedCurveParams(
        code=0x0004,
        named_group=NamedGroup.SECT193R1,
    )
    SECT193R2 = TlsNamedCurveParams(
        code=0x0005,
        named_group=NamedGroup.SECT193R2,
    )
    SECT233K1 = TlsNamedCurveParams(
        code=0x0006,
        named_group=NamedGroup.SECT233K1,
    )
    SECT233R1 = TlsNamedCurveParams(
        code=0x0007,
        named_group=NamedGroup.SECT233R1,
    )
    SECT239K1 = TlsNamedCurveParams(
        code=0x0008,
        named_group=NamedGroup.SECT239K1,
    )
    SECT283K1 = TlsNamedCurveParams(
        code=0x0009,
        named_group=NamedGroup.SECT283K1,
    )
    SECT283R1 = TlsNamedCurveParams(
        code=0x000a,
        named_group=NamedGroup.SECT283R1,
    )
    SECT409K1 = TlsNamedCurveParams(
        code=0x000b,
        named_group=NamedGroup.SECT409K1,
    )
    SECT409R1 = TlsNamedCurveParams(
        code=0x000c,
        named_group=NamedGroup.SECT409R1,
    )
    SECT571K1 = TlsNamedCurveParams(
        code=0x000d,
        named_group=NamedGroup.SECT571K1,
    )
    SECT571R1 = TlsNamedCurveParams(
        code=0x000e,
        named_group=NamedGroup.SECT571R1,
    )
    SECP160K1 = TlsNamedCurveParams(
        code=0x000f,
        named_group=NamedGroup.SECP160K1,
    )
    SECP160R1 = TlsNamedCurveParams(
        code=0x0010,
        named_group=NamedGroup.SECP160R1,
    )
    SECP160R2 = TlsNamedCurveParams(
        code=0x0011,
        named_group=NamedGroup.SECP160R2,
    )
    SECP192K1 = TlsNamedCurveParams(
        code=0x0012,
        named_group=NamedGroup.SECP192K1,
    )
    SECP192R1 = TlsNamedCurveParams(
        code=0x0013,
        named_group=NamedGroup.SECP192R1,
    )
    SECP224K1 = TlsNamedCurveParams(
        code=0x0014,
        named_group=NamedGroup.SECP224K1,
    )
    SECP224R1 = TlsNamedCurveParams(
        code=0x0015,
        named_group=NamedGroup.SECP224R1,
    )
    SECP256K1 = TlsNamedCurveParams(
        code=0x0016,
        named_group=NamedGroup.SECP256K1,
    )
    SECP256R1 = TlsNamedCurveParams(
        code=0x0017,
        named_group=NamedGroup.SECP256R1,
    )
    SECP384R1 = TlsNamedCurveParams(
        code=0x0018,
        named_group=NamedGroup.SECP384R1,
    )
    SECP521R1 = TlsNamedCurveParams(
        code=0x0019,
        named_group=NamedGroup.SECP521R1,
    )

    BRAINPOOLP256R1 = TlsNamedCurveParams(
        code=0x001a,
        named_group=NamedGroup.BRAINPOOLP256R1,
    )
    BRAINPOOLP384R1 = TlsNamedCurveParams(
        code=0x001b,
        named_group=NamedGroup.BRAINPOOLP384R1,
    )
    BRAINPOOLP512R1 = TlsNamedCurveParams(
        code=0x001c,
        named_group=NamedGroup.BRAINPOOLP512R1,
    )
    X25519 = TlsNamedCurveParams(
        code=0x001d,
        named_group=NamedGroup.CURVE25519,
    )
    X448 = TlsNamedCurveParams(
        code=0x001e,
        named_group=NamedGroup.CURVE448,
    )

    FFDHE2048 = TlsNamedCurveParams(
        code=0x0100,
        named_group=NamedGroup.FFDHE2048,
    )
    FFDHE3072 = TlsNamedCurveParams(
        code=0x0101,
        named_group=NamedGroup.FFDHE3072,
    )
    FFDHE4096 = TlsNamedCurveParams(
        code=0x0102,
        named_group=NamedGroup.FFDHE4096,
    )
    FFDHE6144 = TlsNamedCurveParams(
        code=0x0103,
        named_group=NamedGroup.FFDHE6144,
    )
    FFDHE8192 = TlsNamedCurveParams(
        code=0x0104,
        named_group=NamedGroup.FFDHE8192,
    )
    GREASE_0A0A = TlsNamedCurveParams(
        code=0x8a8a,
        named_group=None,
    )
    GREASE_BABA = TlsNamedCurveParams(
        code=0xbaba,
        named_group=None,
    )

    ARBITRARY_EXPLICIT_PRIME_CURVES = TlsNamedCurveParams(
        code=0xff01,
        named_group=None,
    )
    ARBITRARY_EXPLICIT_CHAR2_CURVES = TlsNamedCurveParams(
        code=0xff02,
        named_group=None,
    )


class TlsEllipticCurveVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsNamedCurveFactory,
            fallback_class=None,
            min_byte_num=1, max_byte_num=2 ** 16 - 1
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

        # it possible only when the extension is part of the server hello message
        if parser['extension_length'] == 2:
            parser.parse_parsable('supported_version', TlsProtocolVersionBase)
            return TlsExtensionSupportedVersions([parser['supported_version'], ]), parser.parsed_length
        else:
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

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0804,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA256
    )
    RSA_PSS_RSAE_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0805,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA384
    )
    RSA_PSS_RSAE_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0806,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA512
    )

    ED25519 = HashAndSignatureAlgorithmParam(
        code=0x0807,
        signature_algorithm=Authentication.EDDSA,
        hash_algorithm=MAC.ED25519PH
    )
    ED448 = HashAndSignatureAlgorithmParam(
        code=0x0808,
        signature_algorithm=Authentication.EDDSA,
        hash_algorithm=MAC.ED448PH
    )

    RSA_PSS_PSS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0809,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA256
    )
    RSA_PSS_PSS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x080a,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=MAC.SHA384
    )
    RSA_PSS_PSS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x080b,
        signature_algorithm=Authentication.RSA,
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


class TlsExtensionSignatureAlgorithmsBase(TlsExtensionParsed):
    def __init__(self, hash_and_signature_algorithms):
        super(TlsExtensionSignatureAlgorithmsBase, self).__init__()

        self.hash_and_signature_algorithms = TlsSignatureAndHashAlgorithmVector(hash_and_signature_algorithms)

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSignatureAlgorithmsBase, cls)._parse_header(parsable)

        parser.parse_parsable('hash_and_signature_algorithms', TlsSignatureAndHashAlgorithmVector)

        return cls(parser['hash_and_signature_algorithms']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.hash_and_signature_algorithms)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionSignatureAlgorithms(TlsExtensionSignatureAlgorithmsBase):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SIGNATURE_ALGORITHMS


class TlsExtensionSignatureAlgorithmsCert(TlsExtensionSignatureAlgorithmsBase):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SIGNATURE_ALGORITHMS_CERT


class TlsKeyExchangeVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 16 - 1)


class TlsKeyShareEntry(ParsableBase):
    def __init__(self, group, key_exchange):
        self.group = TlsNamedCurve(group)
        self.key_exchange = TlsKeyExchangeVector(key_exchange)

    def __eq__(self, other):
        return self.group == other.group and self.key_exchange == other.key_exchange

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = ParserBinary(parsable_bytes)

        parser.parse_parsable('group', TlsNamedCurveFactory)
        parser.parse_parsable('key_exchange', TlsKeyExchangeVector)

        return TlsKeyShareEntry(parser['group'], parser['key_exchange']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_parsable(self.group)
        composer.compose_parsable(self.key_exchange)

        return composer.composed_bytes


class TlsKeyShareEntryVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsKeyShareEntry,
            fallback_class=None,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionKeyShare(TlsExtensionParsed):
    def __init__(self, key_share_entries):
        super(TlsExtensionKeyShare, self).__init__()

        self.key_share_entries = TlsKeyShareEntryVector(key_share_entries)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(TlsExtensionKeyShare, cls)._parse_header(parsable_bytes)

        parser.parse_parsable('key_share_entries', TlsKeyShareEntryVector)

        return cls(parser['key_share_entries']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.key_share_entries)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionKeyShareReserved(TlsExtensionKeyShare):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE_RESERVED


class TlsCertificateStatusType(enum.IntEnum):
    OCSP = 1


class TlsCertificateStatusRequestExtensions(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=0,
            max_byte_num=2 ** 16 - 1,
        )


class TlsCertificateStatusRequestResponderId(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
        )


class TlsCertificateStatusRequestResponderIdList(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsCertificateStatusRequestResponderId,
            fallback_class=None,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionCertificateStatusRequest(TlsExtensionParsed):
    def __init__(self, responder_id_list=(), extensions=()):
        super(TlsExtensionCertificateStatusRequest, self).__init__()

        self.responder_id_list = TlsCertificateStatusRequestResponderIdList(responder_id_list)
        self.request_extensions = TlsCertificateStatusRequestExtensions(extensions)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.STATUS_REQUEST

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionCertificateStatusRequest, cls)._parse_header(parsable)
        if parser['extension_length'] == 0:
            return TlsExtensionCertificateStatusRequest(), parser.parsed_length

        parser.parse_numeric('status_type', 1, TlsCertificateStatusType)
        parser.parse_parsable('responder_id_list', TlsCertificateStatusRequestResponderIdList)
        parser.parse_parsable('extensions', TlsCertificateStatusRequestExtensions)

        return TlsExtensionCertificateStatusRequest(
            parser['responder_id_list'],
            parser['extensions'],
        ), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_numeric(TlsCertificateStatusType.OCSP, 1)
        payload_composer.compose_parsable(self.responder_id_list)
        payload_composer.compose_parsable(self.request_extensions)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsRenegotiatedConnection(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=0,
            max_byte_num=2 ** 8 - 1,
        )


class TlsExtensionRenegotiationInfo(TlsExtensionParsed):
    def __init__(self, renegotiated_connection=TlsRenegotiatedConnection([])):
        super(TlsExtensionRenegotiationInfo, self).__init__()

        self.renegotiated_connection = TlsRenegotiatedConnection(renegotiated_connection)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.RENEGOTIATION_INFO

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionRenegotiationInfo, cls)._parse_header(parsable)

        parser.parse_parsable('renegotiated_connection', TlsRenegotiatedConnection)

        return TlsExtensionRenegotiationInfo(parser['renegotiated_connection']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.renegotiated_connection)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionSessionTicket(TlsExtensionParsed):
    def __init__(self, session_ticket=bytearray([])):
        super(TlsExtensionSessionTicket, self).__init__()

        self.session_ticket = bytearray(session_ticket)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SESSION_TICKET

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSessionTicket, cls)._parse_header(parsable)

        parser.parse_bytes('session_ticket', parser['extension_length'])

        return TlsExtensionSessionTicket(parser['session_ticket']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_bytes(self.session_ticket)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsProtocolNameFactory(OpaqueEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsProtocolName

    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=1, max_byte_num=2 ** 8 - 1
        )


class TlsProtocolName(OpaqueEnumComposer, enum.Enum):
    C_WEBRTC = TlsProtocolNameParams(
        code='c-webrtc',
    )
    COAP = TlsProtocolNameParams(
        code='coap',
    )
    FTP = TlsProtocolNameParams(
        code='ftp',
    )
    H2 = TlsProtocolNameParams(
        code='h2',
    )
    H2_14 = TlsProtocolNameParams(
        code='h2-14',
    )
    H2_15 = TlsProtocolNameParams(
        code='h2-15',
    )
    H2_16 = TlsProtocolNameParams(
        code='h2-16',
    )
    H2C = TlsProtocolNameParams(
        code='h2c',
    )
    HTTP_0_9 = TlsProtocolNameParams(
        code='http/0.9',
    )
    HTTP_1_0 = TlsProtocolNameParams(
        code='http/1.0',
    )
    HTTP_1_1 = TlsProtocolNameParams(
        code='http/1.1',
    )
    IMAP = TlsProtocolNameParams(
        code='imap',
    )
    MANAGESIEVE = TlsProtocolNameParams(
        code='managesieve',
    )
    POP3 = TlsProtocolNameParams(
        code='pop3',
    )
    SPDY_1 = TlsProtocolNameParams(
        code='spdy/1',
    )
    SPDY_2 = TlsProtocolNameParams(
        code='spdy/2',
    )
    SPDY_3 = TlsProtocolNameParams(
        code='spdy/3',
    )
    SPDY_3_1 = TlsProtocolNameParams(
        code='spdy/3.1',
    )
    STUN_NAT_DISCOVERY = TlsProtocolNameParams(
        code='stun.nat-discovery',
    )
    STUN_TURN = TlsProtocolNameParams(
        code='stun.turn',
    )
    WEBRTC = TlsProtocolNameParams(
        code='webrtc',
    )
    XMPP_CLIENT = TlsProtocolNameParams(
        code='xmpp-client',
    )
    XMPP_SERVER = TlsProtocolNameParams(
        code='xmpp-server',
    )


class TlsProtocolNameList(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsProtocolNameFactory,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionApplicationLayerProtocolNegotiation(TlsExtensionParsed):
    def __init__(self, protocol_names):
        super(TlsExtensionApplicationLayerProtocolNegotiation, self).__init__()

        self.protocol_names = TlsProtocolNameList(protocol_names)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionApplicationLayerProtocolNegotiation, cls)._parse_header(parsable)

        parser.parse_parsable('protocol_names', TlsProtocolNameList)

        return TlsExtensionApplicationLayerProtocolNegotiation(parser['protocol_names']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.protocol_names)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


TLS_EXTENSION_TYPES_GREASE = [
    extension_type
    for extension_type in TlsExtensionType
    if extension_type.name.startswith('GREASE_')
]


class TlsExtensionGrease(TlsExtensionUnusedData):
    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionGrease, cls)._parse_header_and_data(parsable)

        if parser['extension_type'] not in TLS_EXTENSION_TYPES_GREASE:
            raise InvalidType()

        return TlsExtensionGrease(parser['extension_type'], parser['extension_data']), parser.parsed_length


class TlsExtensionPadding(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.PADDING

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header_and_data(parsable)

        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidType()

        return TlsExtensionPadding(parser['extension_type'], parser['extension_data']), parser.parsed_length


class TlsExtensionExtendedMasterSecret(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.EXTENDED_MASTER_SECRET

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header_and_data(parsable)

        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidType()
        if parser['extension_data']:
            raise InvalidValue()

        return TlsExtensionExtendedMasterSecret(parser['extension_type'], parser['extension_data']), parser.parsed_length


class TlsExtensionRecordSizeLimit(TlsExtensionParsed):
    def __init__(self, record_size_limit):
        super(TlsExtensionRecordSizeLimit, self).__init__()

        self.record_size_limit = record_size_limit

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.RECORD_SIZE_LIMIT

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('record_size_limit', 2)

        return TlsExtensionRecordSizeLimit(parser['record_size_limit']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_numeric(self.record_size_limit, 2)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsPskKeyExchangeMode(OneByteEnumComposer, enum.IntEnum):
    PSK_KE = 0
    PSK_DHE_KE = 1


class TlsPskKeyExchangeModeVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
            numeric_class=TlsPskKeyExchangeMode
        )


class TlsExtensionPskKeyExchangeModes(TlsExtensionParsed):
    def __init__(self, key_exhange_modes):
        super(TlsExtensionPskKeyExchangeModes, self).__init__()

        self.key_exhange_modes = key_exhange_modes

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.PSK_KEY_EXCHANGE_MODES

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_parsable('key_exhange_modes', TlsPskKeyExchangeModeVector)

        return TlsExtensionPskKeyExchangeModes(parser['key_exhange_modes']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.key_exhange_modes)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict(
        [
            (TlsExtensionType.SERVER_NAME, TlsExtensionServerName),
            (TlsExtensionType.STATUS_REQUEST, TlsExtensionCertificateStatusRequest),
            (TlsExtensionType.SUPPORTED_GROUPS, TlsExtensionEllipticCurves),
            (TlsExtensionType.EC_POINT_FORMATS, TlsExtensionECPointFormats),
            (TlsExtensionType.SIGNATURE_ALGORITHMS, TlsExtensionSignatureAlgorithms),
            (TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, TlsExtensionApplicationLayerProtocolNegotiation),
            (TlsExtensionType.PADDING, TlsExtensionPadding),
            (TlsExtensionType.EXTENDED_MASTER_SECRET, TlsExtensionExtendedMasterSecret),
            (TlsExtensionType.RECORD_SIZE_LIMIT, TlsExtensionRecordSizeLimit),
            (TlsExtensionType.SESSION_TICKET, TlsExtensionSessionTicket),
            (TlsExtensionType.KEY_SHARE_RESERVED, TlsExtensionKeyShareReserved),
            (TlsExtensionType.SUPPORTED_VERSIONS, TlsExtensionSupportedVersions),
            (TlsExtensionType.PSK_KEY_EXCHANGE_MODES, TlsExtensionPskKeyExchangeModes),
            (TlsExtensionType.SIGNATURE_ALGORITHMS_CERT, TlsExtensionSignatureAlgorithmsCert),
            (TlsExtensionType.KEY_SHARE, TlsExtensionKeyShare),
            (TlsExtensionType.RENEGOTIATION_INFO, TlsExtensionRenegotiationInfo),
        ] + [
            (extension_type, TlsExtensionGrease)
            for extension_type in TLS_EXTENSION_TYPES_GREASE
        ]
    )

    @classmethod
    def _get_variants(cls):
        variants = collections.OrderedDict(cls._VARIANTS)

        variants.update([
            (extension_type, TlsExtensionUnparsed)
            for extension_type in TlsExtensionType
            if extension_type not in cls._VARIANTS
        ])

        return variants
