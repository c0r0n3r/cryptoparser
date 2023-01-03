# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import collections
import enum
import six
import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.tls.algorithm import (
    TlsCertificateCompressionAlgorithm,
    TlsExtensionType,
    TlsNamedCurve,
    TlsNextProtocolName,
    TlsProtocolName,
    TlsPskKeyExchangeMode,
    TlsTokenBindingParamater,
)

from cryptoparser.common.base import (
    OneByteEnumParsable,
    Opaque,
    OpaqueParam,
    ProtocolVersionMajorMinorBase,
    OpaqueEnumParsable,
    TwoByteEnumParsable,
    VariantParsable,
    Vector,
    VectorEnumCodeNumeric,
    VectorEnumCodeString,
    VectorParamEnumCodeNumeric,
    VectorParamEnumCodeString,
    VectorParamNumeric,
    VectorParamParsable,
    VectorParsable,
    VectorParsableDerived,
)
from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.x509 import SignedCertificateTimestampList
from cryptoparser.tls.algorithm import (
    TlsECPointFormatFactory,
    TlsNamedCurveFactory,
    TlsSignatureAndHashAlgorithmFactory,
)
from cryptoparser.tls.grease import TlsInvalidTypeOneByte, TlsInvalidTypeTwoByte
from cryptoparser.tls.version import TlsProtocolVersion


class TlsExtensionTypeFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsExtensionType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


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
        composer.compose_numeric_enum_coded(self.extension_type)

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
class TlsExtensionServerNameClient(TlsExtensionParsed):
    host_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    name_type = attr.ib(validator=attr.validators.in_(TlsServerNameType), default=TlsServerNameType.HOST_NAME)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SERVER_NAME

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionServerNameClient, cls)._parse_header(parsable)

        parser.parse_numeric('server_name_list_length', 2)
        parser.parse_numeric('server_name_type', 1, TlsServerNameType)
        parser.parse_parsable('server_name', TlsServerName)

        return cls(
            six.ensure_text(bytes(bytearray(parser['server_name'])), 'idna')
        ), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        idna_encoded_host_name = six.ensure_binary(self.host_name, 'idna')

        composer.compose_numeric(3 + len(idna_encoded_host_name), 2)
        composer.compose_numeric(self.name_type, 1)

        composer.compose_bytes(idna_encoded_host_name, 2)

        header_bytes = self._compose_header(composer.composed_length)

        return header_bytes + composer.composed_bytes


@attr.s
class TlsExtensionServerNameServer(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SERVER_NAME


class TlsECPointFormatVector(VectorEnumCodeNumeric):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeNumeric(
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


class TlsEllipticCurveVector(VectorEnumCodeNumeric):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeNumeric(
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
            item_class=TlsProtocolVersion,
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
    selected_version = attr.ib(validator=attr.validators.instance_of(TlsProtocolVersion))

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionSupportedVersionsServer, cls)._parse_header(parsable)

        parser.parse_parsable('selected_version', TlsProtocolVersion)

        return TlsExtensionSupportedVersionsServer(parser['selected_version']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.selected_version)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsSignatureAndHashAlgorithmVector(VectorEnumCodeNumeric):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeNumeric(
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


class TlsExtensionDelegatedCredentials(TlsExtensionSignatureAlgorithmsBase):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.DELEGATED_CREDENTIALS


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

        composer.compose_numeric_enum_coded(self.group)
        composer.compose_parsable(self.key_exchange)

        return composer.composed_bytes


@attr.s
class TlsKeyShareEntryInvalidType(ParsableBase):
    group = attr.ib(validator=attr.validators.instance_of(TlsInvalidTypeTwoByte))
    data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_parsable('group', TlsInvalidTypeTwoByte)
        parser.parse_bytes('data', 2)

        return TlsKeyShareEntryInvalidType(parser['group'], parser['data']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_parsable(self.group)
        composer.compose_bytes(self.data, 2)

        return composer.composed_bytes


class TlsKeyShareEntryVector(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=TlsKeyShareEntry,
            fallback_class=TlsKeyShareEntryInvalidType,
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

        payload_composer.compose_numeric_enum_coded(self.selected_group)

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


class TlsExtensionCertificateStatusRequestClient(TlsExtensionParsed):
    def __init__(self, responder_id_list=(), extensions=()):
        super(TlsExtensionCertificateStatusRequestClient, self).__init__()

        self.responder_id_list = TlsCertificateStatusRequestResponderIdList(responder_id_list)
        self.request_extensions = TlsCertificateStatusRequestExtensions(extensions)

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.STATUS_REQUEST

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionCertificateStatusRequestClient, cls)._parse_header(parsable)

        parser.parse_numeric('status_type', 1, TlsCertificateStatusType)
        parser.parse_parsable('responder_id_list', TlsCertificateStatusRequestResponderIdList)
        parser.parse_parsable('extensions', TlsCertificateStatusRequestExtensions)

        return cls(
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


class TlsExtensionCertificateStatusRequestServer(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.STATUS_REQUEST


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


class TlsProtocolNameList(VectorEnumCodeString):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeString(
            item_class=TlsProtocolNameFactory,
            min_byte_num=2, max_byte_num=2 ** 16 - 1
        )


@attr.s
class TlsExtensionApplicationLayerProtocolBase(TlsExtensionParsed):
    protocol_names = attr.ib(
        converter=TlsProtocolNameList,
        validator=attr.validators.instance_of(TlsProtocolNameList),
    )

    @classmethod
    @abc.abstractmethod
    def get_extension_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionApplicationLayerProtocolBase, cls)._parse_header(parsable)

        parser.parse_parsable('protocol_names', TlsProtocolNameList)

        return cls(parser['protocol_names']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.protocol_names)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionApplicationLayerProtocolNegotiation(TlsExtensionApplicationLayerProtocolBase):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION


class TlsExtensionApplicationLayerProtocolSettings(TlsExtensionApplicationLayerProtocolBase):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.APPLICATION_LAYER_PROTOCOL_SETTINGS


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


class TlsNextProtocolNameList(VectorEnumCodeString):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeString(
            item_class=TlsNextProtocolNameFactory,
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


class TlsExtensionChannelId(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.CHANNEL_ID


class TlsExtensionEncryptThenMAC(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.ENCRYPT_THEN_MAC


class TlsExtensionExtendedMasterSecret(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.EXTENDED_MASTER_SECRET


@attr.s
class TlsExtensionShortRecordHeader(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SHORT_RECORD_HEADER


class TlsTokenBindingProtocolVersion(ProtocolVersionMajorMinorBase):
    pass


class TlsTokenBindingParamaterFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsTokenBindingParamater

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsTokenBindingParamaterVector(VectorEnumCodeNumeric):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeNumeric(
            item_class=TlsTokenBindingParamaterFactory,
            fallback_class=TlsInvalidTypeOneByte,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
        )


@attr.s
class TlsExtensionTokenBinding(TlsExtensionParsed):
    protocol_version = attr.ib(validator=attr.validators.instance_of(TlsTokenBindingProtocolVersion))
    parameters = attr.ib(
        converter=TlsTokenBindingParamaterVector,
        validator=attr.validators.instance_of(TlsTokenBindingParamaterVector)
    )

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.TOKEN_BINDING

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionTokenBinding, cls)._parse_header(parsable)

        parser.parse_parsable('protocol_version', TlsTokenBindingProtocolVersion)
        parser.parse_parsable('parameters', TlsTokenBindingParamaterVector)

        return cls(parser['protocol_version'], parser['parameters']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.protocol_version)
        payload_composer.compose_parsable(self.parameters)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsPskKeyExchangeModeFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsPskKeyExchangeMode

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsPskKeyExchangeModeVector(VectorEnumCodeNumeric):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeNumeric(
            item_class=TlsPskKeyExchangeModeFactory,
            fallback_class=TlsInvalidTypeOneByte,
            min_byte_num=1,
            max_byte_num=2 ** 8 - 1,
        )


@attr.s
class TlsExtensionPskKeyExchangeModes(TlsExtensionParsed):
    key_exchange_modes = attr.ib(
        converter=TlsPskKeyExchangeModeVector,
        validator=attr.validators.instance_of(TlsPskKeyExchangeModeVector)
    )

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.PSK_KEY_EXCHANGE_MODES

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionPskKeyExchangeModes, cls)._parse_header(parsable)

        parser.parse_parsable('key_exchange_modes', TlsPskKeyExchangeModeVector)

        return TlsExtensionPskKeyExchangeModes(parser['key_exchange_modes']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.key_exchange_modes)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


@attr.s
class TlsExtensionRecordSizeLimit(TlsExtensionParsed):
    record_size_limit = attr.ib(validator=attr.validators.instance_of(int))

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


@attr.s
class TlsExtensionSignedCertificateTimestampClient(TlsExtensionUnusedData):
    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP


@attr.s
class TlsExtensionSignedCertificateTimestampServer(TlsExtensionParsed):
    scts = attr.ib(
        converter=SignedCertificateTimestampList,
        validator=attr.validators.optional(attr.validators.instance_of(SignedCertificateTimestampList))
    )

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP

    @classmethod
    def _parse(cls, parsable):
        parser = super(cls, cls)._parse_header(parsable)

        parser.parse_parsable('scts', SignedCertificateTimestampList)

        return cls(parser['scts']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.scts)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsCertificateCompressionAlgorithmFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsCertificateCompressionAlgorithm

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class TlsCertificateCompressionAlgorithmVector(VectorEnumCodeNumeric):
    @classmethod
    def get_param(cls):
        return VectorParamEnumCodeNumeric(
            item_class=TlsCertificateCompressionAlgorithmFactory,
            fallback_class=TlsInvalidTypeTwoByte,
            min_byte_num=2, max_byte_num=2 ** 8 - 2
        )


@attr.s
class TlsExtensionCompressCertificate(TlsExtensionParsed):
    compression_algorithms = attr.ib(
        converter=TlsCertificateCompressionAlgorithmVector,
        validator=attr.validators.instance_of(TlsCertificateCompressionAlgorithmVector),
    )

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.COMPRESS_CERTIFICATE

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionCompressCertificate, cls)._parse_header(parsable)

        parser.parse_parsable('compression_algorithms', TlsCertificateCompressionAlgorithmVector)

        return cls(parser['compression_algorithms']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_parsable(self.compression_algorithms)

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


@attr.s
class TlsExtensionPadding(TlsExtensionParsed):
    length = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    @classmethod
    def get_extension_type(cls):
        return TlsExtensionType.PADDING

    @classmethod
    def _parse(cls, parsable):
        parser = super(TlsExtensionPadding, cls)._parse_header(parsable)

        parser.parse_raw('padding', parser['extension_length'])
        try:
            non_zero_int = next(byte for byte in parser['padding'] if byte != 0)
            raise InvalidValue(six.int2byte(non_zero_int), cls)
        except StopIteration:
            pass

        return cls(parser['extension_length']), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_raw(self.length * b'\x00')

        header_bytes = self._compose_header(payload_composer.composed_length)

        return header_bytes + payload_composer.composed_bytes


class TlsExtensionVariantBase(VariantParsable):
    @classmethod
    @abc.abstractmethod
    def get_parsed_extensions(cls):
        raise NotImplementedError()

    @classmethod
    def _get_variants(cls):
        variants = cls.get_parsed_extensions()

        variants.update([
            (extension_type, (TlsExtensionUnparsed, ))
            for extension_type in TlsExtensionType
            if extension_type not in variants
        ])

        return variants


class TlsExtensionVariantClient(TlsExtensionVariantBase):
    @classmethod
    def get_parsed_extensions(cls):
        return collections.OrderedDict([
            (TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                [TlsExtensionApplicationLayerProtocolNegotiation, ]),
            (TlsExtensionType.APPLICATION_LAYER_PROTOCOL_SETTINGS,
                [TlsExtensionApplicationLayerProtocolSettings, ]),
            (TlsExtensionType.CHANNEL_ID, [TlsExtensionChannelId, ]),
            (TlsExtensionType.COMPRESS_CERTIFICATE, [TlsExtensionCompressCertificate, ]),
            (TlsExtensionType.ENCRYPT_THEN_MAC, [TlsExtensionEncryptThenMAC, ]),
            (TlsExtensionType.EXTENDED_MASTER_SECRET, [TlsExtensionExtendedMasterSecret, ]),
            (TlsExtensionType.RENEGOTIATION_INFO, [TlsExtensionRenegotiationInfo, ]),
            (TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION, [TlsExtensionNextProtocolNegotiationClient, ]),
            (TlsExtensionType.PADDING, [TlsExtensionPadding, ]),
            (TlsExtensionType.SERVER_NAME, [TlsExtensionServerNameClient, ]),
            (TlsExtensionType.SESSION_TICKET, [TlsExtensionSessionTicket, ]),
            (TlsExtensionType.STATUS_REQUEST, [TlsExtensionCertificateStatusRequestClient, ]),
            (TlsExtensionType.SUPPORTED_GROUPS, [TlsExtensionEllipticCurves, ]),
            (TlsExtensionType.DELEGATED_CREDENTIALS, [TlsExtensionDelegatedCredentials, ]),
            (TlsExtensionType.EC_POINT_FORMATS, [TlsExtensionECPointFormats, ]),
            (TlsExtensionType.KEY_SHARE, [TlsExtensionKeyShareClient, ]),
            (TlsExtensionType.KEY_SHARE_RESERVED, [TlsExtensionKeyShareReservedClient, ]),
            (TlsExtensionType.PSK_KEY_EXCHANGE_MODES, [TlsExtensionPskKeyExchangeModes, ]),
            (TlsExtensionType.RECORD_SIZE_LIMIT, [TlsExtensionRecordSizeLimit, ]),
            (TlsExtensionType.SHORT_RECORD_HEADER, [TlsExtensionShortRecordHeader, ]),
            (TlsExtensionType.SIGNATURE_ALGORITHMS, [TlsExtensionSignatureAlgorithms, ]),
            (TlsExtensionType.SIGNATURE_ALGORITHMS_CERT, [TlsExtensionSignatureAlgorithmsCert, ]),
            (TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, [TlsExtensionSignedCertificateTimestampClient, ]),
            (TlsExtensionType.SUPPORTED_VERSIONS, [TlsExtensionSupportedVersionsClient, ]),
            (TlsExtensionType.TOKEN_BINDING, [TlsExtensionTokenBinding, ]),
        ])


class TlsExtensionVariantServer(TlsExtensionVariantBase):
    @classmethod
    def get_parsed_extensions(cls):
        return collections.OrderedDict([
            (TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                [TlsExtensionApplicationLayerProtocolNegotiation, ]),
            (TlsExtensionType.CHANNEL_ID, [TlsExtensionChannelId, ]),
            (TlsExtensionType.EC_POINT_FORMATS, [TlsExtensionECPointFormats, ]),
            (TlsExtensionType.ENCRYPT_THEN_MAC, [TlsExtensionEncryptThenMAC, ]),
            (TlsExtensionType.EXTENDED_MASTER_SECRET, [TlsExtensionExtendedMasterSecret, ]),
            (TlsExtensionType.KEY_SHARE, [TlsExtensionKeyShareClientHelloRetry, TlsExtensionKeyShareServer]),
            (TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION, [TlsExtensionNextProtocolNegotiationServer, ]),
            (TlsExtensionType.RECORD_SIZE_LIMIT, [TlsExtensionRecordSizeLimit, ]),
            (TlsExtensionType.RENEGOTIATION_INFO, [TlsExtensionRenegotiationInfo, ]),
            (TlsExtensionType.SERVER_NAME, [TlsExtensionServerNameServer, ]),
            (TlsExtensionType.SESSION_TICKET, [TlsExtensionSessionTicket, ]),
            (TlsExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, [TlsExtensionSignedCertificateTimestampServer, ]),
            (TlsExtensionType.STATUS_REQUEST, [TlsExtensionCertificateStatusRequestServer, ]),
            (TlsExtensionType.SUPPORTED_VERSIONS, [TlsExtensionSupportedVersionsServer, ]),
        ])
