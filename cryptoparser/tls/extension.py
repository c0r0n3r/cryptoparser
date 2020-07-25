# -*- coding: utf-8 -*-

import abc
import collections
import enum
import six
import attr

from cryptoparser.common.algorithm import Authentication, Hash, NamedGroup
from cryptoparser.common.base import (
    OneByteEnumComposer,
    OneByteEnumParsable,
    Serializable,
    TwoByteEnumComposer,
    TwoByteEnumParsable,
    VariantParsable,
    Vector,
    VectorParamNumeric,
    VectorParamParsable,
    VectorParsable,
    VectorParsableDerived,
)
from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.tls.grease import TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.version import TlsProtocolVersionBase


@attr.s(frozen=True)
class TlsNamedCurveParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    named_group = attr.ib(validator=attr.validators.optional(attr.validators.in_(NamedGroup)))


@attr.s(frozen=True)
class TlsExtensionTypeParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))


@attr.s(frozen=True)
class TlsECPointFormatParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))


class TlsExtensionTypeFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsExtensionType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsExtensionType(Serializable, TwoByteEnumComposer, enum.Enum):
    SERVER_NAME = TlsExtensionTypeParams(                             # [RFC6066]
        code=0x0000
    )
    MAX_FRAGMENT_LENGTH = TlsExtensionTypeParams(                     # [RFC6066]
        code=0x0001
    )
    CLIENT_CERTIFICATE_URL = TlsExtensionTypeParams(                  # [RFC6066]
        code=0x0002
    )
    TRUSTED_CA_KEYS = TlsExtensionTypeParams(                         # [RFC6066]
        code=0x0003
    )
    TRUNCATED_HMAC = TlsExtensionTypeParams(                          # [RFC6066]
        code=0x0004
    )
    STATUS_REQUEST = TlsExtensionTypeParams(                          # [RFC6066]
        code=0x0005
    )
    USER_MAPPING = TlsExtensionTypeParams(                            # [RFC4681]
        code=0x0006
    )
    CLIENT_AUTHZ = TlsExtensionTypeParams(                            # [RFC5878]
        code=0x0007
    )
    SERVER_AUTHZ = TlsExtensionTypeParams(                            # [RFC5878]
        code=0x0008
    )
    CERT_TYPE = TlsExtensionTypeParams(                               # [RFC6091]
        code=0x0009
    )
    SUPPORTED_GROUPS = TlsExtensionTypeParams(                        # [RFC-IETF-TLS-RFC]
        code=0x000a
    )
    EC_POINT_FORMATS = TlsExtensionTypeParams(                        # [RFC-IETF-TLS-RFC]
        code=0x000b
    )
    SRP = TlsExtensionTypeParams(                                     # [RFC5054]
        code=0x000c
    )
    SIGNATURE_ALGORITHMS = TlsExtensionTypeParams(                    # [RFC5246]
        code=0x000d
    )
    USE_SRTP = TlsExtensionTypeParams(                                # [RFC5764]
        code=0x000e
    )
    HEARTBEAT = TlsExtensionTypeParams(                               # [RFC6520]
        code=0x000f
    )
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = TlsExtensionTypeParams(  # [RFC7301]
        code=0x0010
    )
    STATUS_REQUEST_V2 = TlsExtensionTypeParams(                       # [RFC6961]
        code=0x0011
    )
    SIGNED_CERTIFICATE_TIMESTAMP = TlsExtensionTypeParams(            # [RFC6962]
        code=0x0012
    )
    CLIENT_CERTIFICATE_TYPE = TlsExtensionTypeParams(                 # [RFC7250]
        code=0x0013
    )
    SERVER_CERTIFICATE_TYPE = TlsExtensionTypeParams(                 # [RFC7250]
        code=0x0014
    )
    PADDING = TlsExtensionTypeParams(                                 # [RFC7685]
        code=0x0015
    )
    ENCRYPT_THEN_MAC = TlsExtensionTypeParams(                        # [RFC7366]
        code=0x0016
    )
    EXTENDED_MASTER_SECRET = TlsExtensionTypeParams(                  # [RFC7627]
        code=0x0017
    )
    TOKEN_BINDING = TlsExtensionTypeParams(                           # [DRAFT-IETF-TOKBIND-NEGOTIATION]
        code=0x0018
    )
    CACHED_INFO = TlsExtensionTypeParams(                             # [RFC7924]
        code=0x0019
    )
    COMPRESS_CERTIFICATE = TlsExtensionTypeParams(                    # [RFC-ietf-tls-certificate-compression-09]
        code=0x001b
    )
    RECORD_SIZE_LIMIT = TlsExtensionTypeParams(                       # [RFC8849]
        code=0x001c
    )
    PWD_PROTECT = TlsExtensionTypeParams(                             # [RFC-HARKINS-TLS-DRAGONFLY-03]
        code=0x001d
    )
    PWD_CLEAR = TlsExtensionTypeParams(                               # [RFC-HARKINS-TLS-DRAGONFLY-03]
        code=0x001e
    )
    PASSWORD_SALT = TlsExtensionTypeParams(                           # [RFC-HARKINS-TLS-DRAGONFLY-03]
        code=0x001f
    )
    TICKET_PINNING = TlsExtensionTypeParams(                          # [RFC8672]
        code=0x0020
    )
    TLS_CERT_WITH_EXTERN_PSK = TlsExtensionTypeParams(                # [RFC-IETF-TLS-TLS13-CERT-WITH-EXTERN-PSK-07]
        code=0x0021
    )
    SESSION_TICKET = TlsExtensionTypeParams(                          # [RFC4507]
        code=0x0023
    )
    KEY_SHARE_RESERVED = TlsExtensionTypeParams(                      # [DRAFT-IETF-TLS-TLS13-20]
        code=0x0028
    )
    PRE_SHARED_KEY = TlsExtensionTypeParams(                          # [DRAFT-IETF-TLS-TLS13-20]
        code=0x0029
    )
    EARLY_DATA = TlsExtensionTypeParams(                              # [DRAFT-IETF-TLS-TLS13-20]
        code=0x002a
    )
    SUPPORTED_VERSIONS = TlsExtensionTypeParams(                      # [DRAFT-IETF-TLS-TLS13-20]
        code=0x002b
    )
    COOKIE = TlsExtensionTypeParams(                                  # [DRAFT-IETF-TLS-TLS13-20]
        code=0x002c
    )
    PSK_KEY_EXCHANGE_MODES = TlsExtensionTypeParams(                  # [DRAFT-IETF-TLS-TLS13-20]
        code=0x002d
    )
    CERTIFICATE_AUTHORITIES = TlsExtensionTypeParams(                 # [DRAFT-IETF-TLS-TLS13-20]
        code=0x002f
    )
    OID_FILTERS = TlsExtensionTypeParams(                             # [DRAFT-IETF-TLS-TLS13-20]
        code=0x0030
    )
    POST_HANDSHAKE_AUTH = TlsExtensionTypeParams(                     # [DRAFT-IETF-TLS-TLS13-20]
        code=0x0031
    )
    SIGNATURE_ALGORITHMS_CERT = TlsExtensionTypeParams(               # [DRAFT-IETF-TLS-TLS13-23]
        code=0x0032
    )
    KEY_SHARE = TlsExtensionTypeParams(                               # [DRAFT-IETF-TLS-TLS13-23]
        code=0x0033
    )
    TRANSPARENCY_INFO = TlsExtensionTypeParams(                       # [DRAFT-IETF-TRANS-RFC6962-BIS]
        code=0x0034
    )
    CONNECTION_ID = TlsExtensionTypeParams(                           # [DRAFT-IETF-TLS-DTLS-CONNECTION-ID]
        code=0x0035
    )
    EXTERNAL_ID_HASH = TlsExtensionTypeParams(                        # [RFC-IETF-MMUSIC-SDP-UKS-07]
        code=0x0037
    )
    EXTERNAL_SESSION_ID = TlsExtensionTypeParams(                     # [RFC-IETF-MMUSIC-SDP-UKS-07]
        code=0x0038
    )
    NEXT_PROTOCOL_NEGOTIATION = TlsExtensionTypeParams(               # [DRAFT-AGL-TLS-NEXTPROTONEG-04]
        code=0x3374
    )
    CHANNEL_ID = TlsExtensionTypeParams(                              # [DRAFT-BALFANZ-TLS-OBC-01]
        code=0x7550
    )
    RENEGOTIATION_INFO = TlsExtensionTypeParams(                      # [DRAFT-AGL-TLS-NEXTPROTONEG-03]
        code=0xff01
    )
    RECORD_HEADER = TlsExtensionTypeParams(                           # [DRAFT-FOSSATI-TLS-EXT-HEADER]
        code=0xff03
    )


class TlsExtensions(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsExtensionVariant,
            fallback_class=TlsExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


@attr.s
class TlsExtensionBase(ParsableBase):
    extension_type = attr.ib(init=False, validator=attr.validators.instance_of(TlsExtensionType))

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_type(cls, parser, name):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_type(self, composer):
        raise NotImplementedError()

    @classmethod
    def _check_header(cls, parsable):
        parser = ParserBinary(parsable)

        cls._parse_type(parser, 'extension_type')
        parser.parse_numeric('extension_length', 2)

        if parser.unparsed_length < parser['extension_length']:
            raise NotEnoughData(parser['extension_length'] + parser.parsed_length)

        return parser

    def _compose_header(self, payload_length):
        header_composer = ComposerBinary()

        self._compose_type(header_composer)
        header_composer.compose_numeric(payload_length, 2)

        return header_composer.composed_bytes


@attr.s
class TlsExtensionUnparsed(TlsExtensionBase):
    extension_type = attr.ib(validator=attr.validators.instance_of((TlsExtensionType, TlsInvalidTypeTwoByte)))
    extension_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse_type(cls, parser, name):
        parser.parse_parsable(name, TlsInvalidTypeTwoByte)

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionUnparsed, cls)._check_header(parsable)

        parser.parse_bytes('extension_data', parser['extension_length'])

        return TlsExtensionUnparsed(parser['extension_type'], parser['extension_data']), parser.parsed_length

    def _compose_type(self, composer):
        composer.compose_parsable(self.extension_type)

    def compose(self):
        payload_composer = ComposerBinary()
        payload_composer.compose_bytes(self.extension_data)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


@attr.s
class TlsExtensionParsed(TlsExtensionBase):
    def __attrs_post_init__(self):
        self.extension_type = self.get_extension_type()

        attr.validate(self)

    @classmethod
    def _parse_type(cls, parser, name):
        parser.parse_parsable(name, TlsExtensionTypeFactory)

    def _compose_type(self, composer):
        composer.compose_parsable(self.extension_type)

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = super(TlsExtensionParsed, cls)._check_header(parsable)

        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidType()

        return parser


class TlsServerNameType(enum.IntEnum):
    HOST_NAME = 0x00


class TlsServerName(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(
            item_size=1,
            min_byte_num=1,
            max_byte_num=2 ** 16 - 1,
        )


@attr.s
class TlsExtensionServerName(TlsExtensionParsed):
    host_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    name_type = attr.ib(validator=attr.validators.in_(TlsServerNameType), default=TlsServerNameType.HOST_NAME)

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


class TlsECPointFormatFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsECPointFormat

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsECPointFormat(Serializable, OneByteEnumComposer, enum.Enum):
    UNCOMPRESSED = TlsECPointFormatParams(code=0x00)
    ANSIX962_COMPRESSED_PRIME = TlsECPointFormatParams(code=0x01)
    ANSIX962_COMPRESSED_CHAR2 = TlsECPointFormatParams(code=0x02)


class TlsECPointFormatVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsECPointFormatFactory,
            fallback_class=TlsInvalidTypeOneByte,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
        )


@attr.s
class TlsExtensionECPointFormats(TlsExtensionParsed):
    point_formats = attr.ib(
        converter=TlsECPointFormatVector,
        validator=attr.validators.instance_of(TlsECPointFormatVector)
    )

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


class TlsNamedCurve(TwoByteEnumComposer):
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
        named_group=NamedGroup.PRIME192V1,
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
        named_group=NamedGroup.PRIME256V1,
    )
    SECP384R1 = TlsNamedCurveParams(
        code=0x0018,
        named_group=NamedGroup.SECP384R1,
    )
    SECP521R1 = TlsNamedCurveParams(
        code=0x0019,
        named_group=NamedGroup.SECP521R1,
    )
    GC256A = TlsNamedCurveParams(
        code=0x0022,
        named_group=NamedGroup.GC256A,
    )
    GC256B = TlsNamedCurveParams(
        code=0x0023,
        named_group=NamedGroup.GC256B,
    )
    GC256C = TlsNamedCurveParams(
        code=0x0024,
        named_group=NamedGroup.GC256C,
    )
    GC256D = TlsNamedCurveParams(
        code=0x0025,
        named_group=NamedGroup.GC256D,
    )
    GC512A = TlsNamedCurveParams(
        code=0x0026,
        named_group=NamedGroup.GC512A,
    )
    GC512B = TlsNamedCurveParams(
        code=0x0027,
        named_group=NamedGroup.GC512B,
    )
    GC512C = TlsNamedCurveParams(
        code=0x0028,
        named_group=NamedGroup.GC512C,
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
            fallback_class=TlsInvalidTypeTwoByte,
            min_byte_num=1, max_byte_num=2 ** 16 - 1
        )


@attr.s
class TlsExtensionEllipticCurves(TlsExtensionParsed):
    elliptic_curves = attr.ib(
        converter=TlsEllipticCurveVector,
        validator=attr.validators.instance_of(TlsEllipticCurveVector)
    )

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
            fallback_class=TlsInvalidTypeTwoByte,
            min_byte_num=2, max_byte_num=2 ** 8 - 2
        )


@attr.s
class TlsExtensionSupportedVersions(TlsExtensionParsed):
    supported_versions = attr.ib(validator=attr.validators.instance_of(TlsSupportedVersionVector))

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


@attr.s(frozen=True)
class HashAndSignatureAlgorithmParam(object):
    code = attr.ib(validator=attr.validators.instance_of(int))
    hash_algorithm = attr.ib(validator=attr.validators.optional(attr.validators.in_(Hash)))
    signature_algorithm = attr.ib(validator=attr.validators.optional(attr.validators.in_(Authentication)))


class TlsSignatureAndHashAlgorithm(TwoByteEnumComposer):
    ANONYMOUS_NONE = HashAndSignatureAlgorithmParam(
        code=0x0000,
        signature_algorithm=Authentication.anon,
        hash_algorithm=None,
    )
    ANONYMOUS_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0100,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.MD5
    )
    ANONYMOUS_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0200,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA1
    )
    ANONYMOUS_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0300,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_224
    )
    ANONYMOUS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0400,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_256
    )
    ANONYMOUS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0500,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_384
    )
    ANONYMOUS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0006,
        signature_algorithm=Authentication.anon,
        hash_algorithm=Hash.SHA2_512
    )
    RSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0001,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=None,
    )
    RSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0101,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.MD5
    )
    RSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0201,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA1
    )
    RSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0301,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_224
    )
    RSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0401,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0501,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0601,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )
    DSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0002,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=None,
    )
    DSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0102,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.MD5
    )
    DSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0202,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA1
    )
    DSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0302,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_224
    )
    DSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0402,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_256
    )
    DSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0502,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_384
    )
    DSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0602,
        signature_algorithm=Authentication.DSS,
        hash_algorithm=Hash.SHA2_512
    )
    ECDSA_NONE = HashAndSignatureAlgorithmParam(
        code=0x0003,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=None,
    )
    ECDSA_MD5 = HashAndSignatureAlgorithmParam(
        code=0x0103,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.MD5
    )
    ECDSA_SHA1 = HashAndSignatureAlgorithmParam(
        code=0x0203,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA1
    )
    ECDSA_SHA224 = HashAndSignatureAlgorithmParam(
        code=0x0303,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_224
    )
    ECDSA_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0403,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_256
    )
    ECDSA_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0503,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_384
    )
    ECDSA_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0603,
        signature_algorithm=Authentication.ECDSA,
        hash_algorithm=Hash.SHA2_512
    )
    GOST_R3410_01 = HashAndSignatureAlgorithmParam(
        code=0x00ed,
        signature_algorithm=Authentication.GOST_R3410_01,
        hash_algorithm=Hash.GOST_R3411_94,
    )
    OLD_GOST_R3410_12_256 = HashAndSignatureAlgorithmParam(
        code=0x00ee,
        signature_algorithm=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    OLD_GOST_R3410_12_512 = HashAndSignatureAlgorithmParam(
        code=0x00ef,
        signature_algorithm=Authentication.GOST_R3410_12_512,
        hash_algorithm=Hash.GOST_R3411_12_512,
    )
    GOST_R3410_12_256 = HashAndSignatureAlgorithmParam(
        code=0x4008,
        signature_algorithm=Authentication.GOST_R3410_12_256,
        hash_algorithm=Hash.GOST_R3411_12_256,
    )
    GOST_R3410_12_512 = HashAndSignatureAlgorithmParam(
        code=0x4108,
        signature_algorithm=Authentication.GOST_R3410_12_512,
        hash_algorithm=Hash.GOST_R3411_12_512,
    )

    RSA_PSS_RSAE_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0804,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_PSS_RSAE_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x0805,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_PSS_RSAE_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x0806,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )

    ED25519 = HashAndSignatureAlgorithmParam(
        code=0x0807,
        signature_algorithm=Authentication.EDDSA,
        hash_algorithm=Hash.ED25519PH
    )
    ED448 = HashAndSignatureAlgorithmParam(
        code=0x0808,
        signature_algorithm=Authentication.EDDSA,
        hash_algorithm=Hash.ED448PH
    )

    RSA_PSS_PSS_SHA256 = HashAndSignatureAlgorithmParam(
        code=0x0809,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_256
    )
    RSA_PSS_PSS_SHA384 = HashAndSignatureAlgorithmParam(
        code=0x080a,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_384
    )
    RSA_PSS_PSS_SHA512 = HashAndSignatureAlgorithmParam(
        code=0x080b,
        signature_algorithm=Authentication.RSA,
        hash_algorithm=Hash.SHA2_512
    )


class TlsSignatureAndHashAlgorithmVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsSignatureAndHashAlgorithmFactory,
            fallback_class=TlsInvalidTypeTwoByte,
            min_byte_num=2, max_byte_num=2 ** 16 - 2
        )


@attr.s
class TlsExtensionSignatureAlgorithms(TlsExtensionParsed):
    hash_and_signature_algorithms = attr.ib(
        converter=TlsSignatureAndHashAlgorithmVector,
        validator=attr.validators.instance_of(TlsSignatureAndHashAlgorithmVector)
    )

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


class TlsExtensionVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict(
        [
            (TlsExtensionType.SERVER_NAME, (TlsExtensionServerName, )),
            (TlsExtensionType.SUPPORTED_GROUPS, (TlsExtensionEllipticCurves, )),
            (TlsExtensionType.EC_POINT_FORMATS, (TlsExtensionECPointFormats, )),
            (TlsExtensionType.SIGNATURE_ALGORITHMS, (TlsExtensionSignatureAlgorithms, )),
            (TlsExtensionType.SUPPORTED_VERSIONS, (TlsExtensionSupportedVersions, )),
        ]
    )

    @classmethod
    def _get_variants(cls):
        variants = collections.OrderedDict(cls._VARIANTS)

        variants.update([
            (extension_type, (TlsExtensionUnparsed, ))
            for extension_type in TlsExtensionType
            if extension_type not in cls._VARIANTS
        ])

        return variants
