# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import collections
import enum
import six
import attr

from cryptoparser.tls.algorithm import TlsNextProtocolName, TlsProtocolName
from cryptoparser.common.base import (
    Opaque,
    OpaqueParam,
    TwoByteEnumComposer,
    OpaqueEnumParsable,
    TwoByteEnumParsable,
    VariantParsable,
    Vector,
    VectorParamNumeric,
    VectorParamParsable,
    VectorParsable,
    VectorParsableDerived,
)
from cryptoparser.common.exception import NotEnoughData, InvalidType, InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.tls.algorithm import (
    TlsNamedCurve,
    TlsNamedCurveFactory,
    TlsECPointFormatFactory,
    TlsSignatureAndHashAlgorithmFactory
)
from cryptoparser.tls.grease import TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.version import TlsProtocolVersionBase


@attr.s(frozen=True)
class TlsExtensionTypeParams(object):
    code = attr.ib(validator=attr.validators.instance_of(int))


class TlsExtensionTypeFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsExtensionType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsExtensionType(TwoByteEnumComposer, enum.Enum):
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


class TlsExtensionsBase(VectorParsable):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def get_item_by_type(self, extension_type):
        try:
            item = next(
                extension
                for extension in self
                if extension.extension_type == extension_type
            )
        except StopIteration as e:
            six.raise_from(KeyError, e)

        return item


class TlsExtensionsClient(TlsExtensionsBase):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsExtensionVariantClient,
            fallback_class=TlsExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 16 - 1
        )


class TlsExtensionsServer(TlsExtensionsBase):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsExtensionVariantServer,
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
        parser = cls._check_header(parsable)

        parser.parse_raw('extension_data', parser['extension_length'])

        return TlsExtensionUnparsed(parser['extension_type'], parser['extension_data']), parser.parsed_length

    def _compose_type(self, composer):
        composer.compose_parsable(self.extension_type)

    def compose(self):
        return self._compose_header(len(self.extension_data)) + self.extension_data


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


class TlsExtensionUnusedData(TlsExtensionParsed):
    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_raw('extension_data', parser['extension_length'])

        if parser['extension_data']:
            raise InvalidValue(parser['extension_data'], cls)

        return cls(), parser.parsed_length

    def compose(self):
        return self._compose_header(0)

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()


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

            composer.compose_bytes(idna_encoded_host_name, 2)

        header_bytes = self._compose_header(composer.composed_length)

        return header_bytes + composer.composed_bytes


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
class TlsExtensionSupportedVersionsBase(TlsExtensionParsed):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SUPPORTED_VERSIONS

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class TlsExtensionSupportedVersionsClient(TlsExtensionSupportedVersionsBase):
    supported_versions = attr.ib(
        converter=TlsSupportedVersionVector,
        validator=attr.validators.instance_of(TlsSupportedVersionVector)
    )

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSupportedVersionsClient, cls)._parse_header(parsable)

        parser.parse_parsable('supported_versions', TlsSupportedVersionVector)

        return TlsExtensionSupportedVersionsClient(parser['supported_versions']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.supported_versions)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


@attr.s
class TlsExtensionSupportedVersionsServer(TlsExtensionSupportedVersionsBase):
    selected_version = attr.ib(validator=attr.validators.instance_of(TlsProtocolVersionBase))

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSupportedVersionsServer, cls)._parse_header(parsable)

        parser.parse_parsable('selected_version', TlsProtocolVersionBase)

        return TlsExtensionSupportedVersionsServer(parser['selected_version']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.selected_version)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsSignatureAndHashAlgorithmVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsSignatureAndHashAlgorithmFactory,
            fallback_class=TlsInvalidTypeTwoByte,
            min_byte_num=2, max_byte_num=2 ** 16 - 2
        )


@attr.s
class TlsExtensionSignatureAlgorithmsBase(TlsExtensionParsed):
    hash_and_signature_algorithms = attr.ib(
        converter=TlsSignatureAndHashAlgorithmVector,
        validator=attr.validators.instance_of(TlsSignatureAndHashAlgorithmVector)
    )

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

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


@attr.s
class TlsKeyShareEntry(ParsableBase):
    group = attr.ib(validator=attr.validators.instance_of(TlsNamedCurve))
    key_exchange = attr.ib(converter=TlsKeyExchangeVector)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

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


class TlsExtensionKeyShareBase(TlsExtensionParsed):
    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class TlsExtensionKeyShareServer(TlsExtensionKeyShareBase):
    key_share_entry = attr.ib(validator=attr.validators.instance_of(TlsKeyShareEntry))

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionKeyShareServer, cls)._parse_header(parsable)

        parser.parse_parsable('key_share_entry', TlsKeyShareEntry)

        return TlsExtensionKeyShareServer(parser['key_share_entry']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.key_share_entry)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


@attr.s
class TlsExtensionKeyShareClientHelloRetry(TlsExtensionKeyShareBase):
    selected_group = attr.ib(converter=TlsNamedCurve)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionKeyShareClientHelloRetry, cls)._parse_header(parsable)

        if parser['extension_length'] != 2:
            raise InvalidType()

        parser.parse_parsable('selected_group', TlsNamedCurveFactory)

        return cls(parser['selected_group']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.selected_group)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


@attr.s
class TlsExtensionKeyShareEntriesClientBase(TlsExtensionKeyShareBase):
    key_share_entries = attr.ib(converter=TlsKeyShareEntryVector)

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionKeyShareEntriesClientBase, cls)._parse_header(parsable)

        parser.parse_parsable('key_share_entries', TlsKeyShareEntryVector)

        return cls(parser['key_share_entries']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.key_share_entries)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionKeyShareClient(TlsExtensionKeyShareEntriesClientBase):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.KEY_SHARE


class TlsExtensionKeyShareReservedClient(TlsExtensionKeyShareEntriesClientBase):
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


class TlsCertificateStatusRequestResponderId(Opaque):
    @classmethod
    def get_param(cls):
        return OpaqueParam(
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


@attr.s
class TlsExtensionRenegotiationInfo(TlsExtensionParsed):
    renegotiated_connection = attr.ib(
        default=TlsRenegotiatedConnection([]),
        validator=attr.validators.instance_of(TlsRenegotiatedConnection)
    )

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


@attr.s
class TlsExtensionSessionTicket(TlsExtensionParsed):
    session_ticket = attr.ib(
        default=bytearray([]),
        validator=attr.validators.instance_of((bytes, bytearray))
    )

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SESSION_TICKET

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSessionTicket, cls)._parse_header(parsable)

        parser.parse_raw('session_ticket', parser['extension_length'])

        return TlsExtensionSessionTicket(parser['session_ticket']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_raw(self.session_ticket)

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


class TlsProtocolNameList(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsProtocolNameFactory,
            fallback_class=None,
            min_byte_num=2, max_byte_num=2 ** 16 - 1
        )


@attr.s
class TlsExtensionApplicationLayerProtocolNegotiation(TlsExtensionParsed):
    protocol_names = attr.ib(
        converter=TlsProtocolNameList,
        validator=attr.validators.instance_of(TlsProtocolNameList),
    )

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


class TlsExtensionNextProtocolNegotiationClient(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION


class TlsNextProtocolNameFactory(OpaqueEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsNextProtocolName

    @classmethod
    def get_param(cls):
        return OpaqueParam(
            min_byte_num=1, max_byte_num=2 ** 8 - 1
        )


class TlsNextProtocolNameList(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsNextProtocolNameFactory,
            fallback_class=None,
            min_byte_num=1, max_byte_num=2 ** 16 - 1
        )


@attr.s
class TlsExtensionNextProtocolNegotiationServer(TlsExtensionParsed):
    protocol_names = attr.ib(
        converter=TlsNextProtocolNameList,
        validator=attr.validators.instance_of(TlsNextProtocolNameList),
    )

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        cls._parse_type(parser, 'extension_type')
        if parser['extension_type'] != cls.get_extension_type():
            raise InvalidType()

        parser.parse_parsable('protocol_names', TlsNextProtocolNameList)

        return cls(parser['protocol_names']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()
        payload_composer.compose_parsable(self.protocol_names)

        header_composer = ComposerBinary()
        self._compose_type(header_composer)

        return header_composer.composed_bytes + payload_composer.composed_bytes


class TlsExtensionEncryptThenMAC(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.ENCRYPT_THEN_MAC


class TlsExtensionExtendedMasterSecret(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.EXTENDED_MASTER_SECRET


class TlsExtensionVariantBase(VariantParsable):
    @classmethod
    @abc.abstractmethod
    def _get_parsed_extensions(cls):
        raise NotImplementedError()

    @classmethod
    def _get_variants(cls):
        variants = cls._get_parsed_extensions()

        variants.update([
            (extension_type, (TlsExtensionUnparsed, ))
            for extension_type in TlsExtensionType
            if extension_type not in variants
        ])

        return variants


class TlsExtensionVariantClient(TlsExtensionVariantBase):
    @classmethod
    def _get_parsed_extensions(cls):
        return collections.OrderedDict([
            (TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                [TlsExtensionApplicationLayerProtocolNegotiation, ]),
            (TlsExtensionType.ENCRYPT_THEN_MAC, [TlsExtensionEncryptThenMAC, ]),
            (TlsExtensionType.EXTENDED_MASTER_SECRET, [TlsExtensionExtendedMasterSecret, ]),
            (TlsExtensionType.RENEGOTIATION_INFO, [TlsExtensionRenegotiationInfo, ]),
            (TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION, [TlsExtensionNextProtocolNegotiationClient, ]),
            (TlsExtensionType.SERVER_NAME, [TlsExtensionServerName, ]),
            (TlsExtensionType.SESSION_TICKET, [TlsExtensionSessionTicket, ]),
            (TlsExtensionType.SUPPORTED_GROUPS, [TlsExtensionEllipticCurves, ]),
            (TlsExtensionType.EC_POINT_FORMATS, [TlsExtensionECPointFormats, ]),
            (TlsExtensionType.KEY_SHARE, [TlsExtensionKeyShareClient, ]),
            (TlsExtensionType.SIGNATURE_ALGORITHMS, [TlsExtensionSignatureAlgorithms, ]),
            (TlsExtensionType.SUPPORTED_VERSIONS, [TlsExtensionSupportedVersionsClient, ]),
        ])


class TlsExtensionVariantServer(TlsExtensionVariantBase):
    @classmethod
    def _get_parsed_extensions(cls):
        return collections.OrderedDict([
            (TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                [TlsExtensionApplicationLayerProtocolNegotiation, ]),
            (TlsExtensionType.EC_POINT_FORMATS, [TlsExtensionECPointFormats, ]),
            (TlsExtensionType.ENCRYPT_THEN_MAC, [TlsExtensionEncryptThenMAC, ]),
            (TlsExtensionType.EXTENDED_MASTER_SECRET, [TlsExtensionExtendedMasterSecret, ]),
            (TlsExtensionType.KEY_SHARE, [TlsExtensionKeyShareClientHelloRetry, TlsExtensionKeyShareServer]),
            (TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION, [TlsExtensionNextProtocolNegotiationServer, ]),
            (TlsExtensionType.RENEGOTIATION_INFO, [TlsExtensionRenegotiationInfo, ]),
            (TlsExtensionType.SESSION_TICKET, [TlsExtensionSessionTicket, ]),
            (TlsExtensionType.SUPPORTED_VERSIONS, [TlsExtensionSupportedVersionsServer, ]),
        ])
