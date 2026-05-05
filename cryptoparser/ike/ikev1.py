# SPDX-License-Identifier: MPL-2.0
"""IKEv1 payload parsers."""

import abc
import collections
import enum
import typing

import attr

from cryptodatahub.ike.algorithm import (
    Ikev1PayloadType,
    Ikev1ProtocolId,
    Ikev1EncryptionAlgorithm,
    Ikev1HashAlgorithm,
    Ikev1TransformId,
    Ikev1AttributeType,
    Ikev1Doi,
    Ikev1DiffieHellmanGroup,
    Ikev1AuthenticationMethod,
    Ikev1LifeType,
    Ikev1NotifyType,
)
from cryptoparser.common.base import VariantParsable
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData
from cryptoparser.ike.common import (
    DataAttributeBase,
    DataAttributeKeyLength,
    DataAttributeLength,
    DataAttributeTypeValueEnumCoded,
    DataAttributeFormat,
)


@attr.s
class Ikev1PayloadBase(ParsableBase):
    """Payload header parser, according to RFC2408.

    The generic payload header has the following structure:

    .. code-block:: text

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Next Payload  |    RESERVED   |         Payload Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :cvar HEADER_SIZE: Size of the header in bytes
    :ivar next_payload: Type of the next payload (1 byte)
    """
    HEADER_SIZE = 4

    next_payload: typing.Optional[Ikev1PayloadType] = attr.ib(
        init=False,
        default=Ikev1PayloadType.NONE,
        validator=attr.validators.optional(attr.validators.instance_of(Ikev1PayloadType))
    )

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_payload_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        """Parse payload header from bytes.

        :param parsable: Bytes to parse
        :type parsable: bytes
        :return: Tuple of (parsed header, number of bytes parsed)
        :rtype: tuple(PayloadBase, int)
        :raises NotEnoughData: If there are not enough bytes to parse
        """
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_numeric_enum_coded('next_payload', Ikev1PayloadType)
        parser.parse_numeric('reserved', 1)  # Skip reserved byte
        parser.parse_numeric('payload_length', 2)

        if parser.unparsed_length < parser['payload_length'] - cls.HEADER_SIZE:
            raise NotEnoughData(parser['payload_length'] - cls.HEADER_SIZE - parser.unparsed_length)

        return parser

    def compose_header(self, payload_length):
        """Compose payload header to bytes.

        :return: Composed header bytes
        :rtype: bytes
        """
        composer = ComposerBinary()
        composer.compose_numeric_enum_coded(self.next_payload)
        composer.compose_numeric(0, 1)  # Reserved byte
        composer.compose_numeric(self.HEADER_SIZE + payload_length, 2)

        return composer


@attr.s
class Ikev1AttributeAuthenticationMethod(DataAttributeTypeValueEnumCoded):
    """Authentication Method transform attribute (TLV format)."""

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.AUTHENTICATION_METHOD

    @classmethod
    def _get_enum_type(cls):
        return Ikev1AuthenticationMethod


@attr.s
class Ikev1AttributeDiffieHellmanGroup(DataAttributeTypeValueEnumCoded):
    """Diffie-Hellman Group transform attribute (TLV format)."""

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.GROUP_DESCRIPTION

    @classmethod
    def _get_enum_type(cls):
        return Ikev1DiffieHellmanGroup


@attr.s
class Ikev1AttributeKeyLength(DataAttributeKeyLength):
    """Key Length transform attribute (TV format)."""

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.KEY_LENGTH


@attr.s
class Ikev1AttributeEncryptionAlgorithm(DataAttributeTypeValueEnumCoded):
    """Encryption Algorithm transform attribute (TLV format)."""

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.ENCRYPTION_ALGORITHM

    @classmethod
    def _get_enum_type(cls):
        return Ikev1EncryptionAlgorithm


@attr.s
class Ikev1AttributeHashAlgorithm(DataAttributeTypeValueEnumCoded):
    """Hash Algorithm transform attribute (TLV format)."""

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.HASH_ALGORITHM

    @classmethod
    def _get_enum_type(cls):
        return Ikev1HashAlgorithm


@attr.s
class Ikev1AttributeLifeType(DataAttributeTypeValueEnumCoded):
    """Life Type transform attribute (TLV format)."""

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.LIFE_TYPE

    @classmethod
    def _get_enum_type(cls):
        return Ikev1LifeType


@attr.s
class Ikev1AttributeLifeDuration(DataAttributeLength):
    """Lifetime transform attribute (TLV format)."""

    @classmethod
    def _get_format(cls):
        return DataAttributeFormat.TYPE_LENGTH_VALUE

    @classmethod
    def get_type(cls):
        return Ikev1AttributeType.LIFE_DURATION

    @classmethod
    def _get_size(cls):
        return 4


@attr.s
class Ikev1PayloadTransform(Ikev1PayloadBase):
    """Transform Payload parser.

    The Transform Payload has the following format:

    .. code-block:: text

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |    RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Transform #  |  Transform-Id |           RESERVED2           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                        SA Attributes                          ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar transform_number: Transform number (1 byte)
    :ivar transform_id: Transform ID (1 byte)
    :ivar sa_attributes: Security Association attributes (variable length)
    """

    transform_id: Ikev1TransformId = attr.ib(validator=attr.validators.instance_of(Ikev1TransformId))
    attributes: typing.List[DataAttributeBase] = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DataAttributeBase),
        )
    )
    transform_number: typing.Optional[int] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.TRANSFORM

    def get_attribute_by_type(self, attribute_type: Ikev1AttributeType) -> DataAttributeBase:
        for attribute in self.attributes:
            if attribute.get_type() == attribute_type:
                return attribute
        raise KeyError(attribute_type)

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('transform_number', 1)
        parser.parse_numeric_enum_coded('transform_id', Ikev1TransformId)
        parser.parse_numeric('reserved2', 2)  # Skip reserved2 field

        attributes = []
        parser_attributes = ParserBinary(parsable[parser.parsed_length:parser['payload_length']])
        while parser_attributes.unparsed_length > 0:
            parser_attributes.parse_parsable('attribute', Ikev1AttributeVariantServer)
            attribute = parser_attributes['attribute']
            attributes.append(attribute)

        payload = cls(
            transform_id=parser['transform_id'],
            attributes=attributes
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length + parser_attributes.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_numeric(self.transform_number, 1)
        composer_payload.compose_numeric_enum_coded(self.transform_id)
        composer_payload.compose_numeric(0, 2)  # Reserved2 field

        for attribute in self.attributes:
            composer_payload.compose_parsable(attribute)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadProposal(Ikev1PayloadBase):
    """Proposal Payload parser.

    The Proposal Payload has the following format:

    .. code-block:: text

                          1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |    RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Proposal #   |  Protocol-Id  |    SPI Size   |# of Transforms|
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        SPI (variable)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar next_payload: Next payload type (1 byte)
    :ivar protocol_id: Protocol ID (1 byte)
    :ivar spi_size: Size of SPI in bytes (1 byte)
    :ivar transform_count: Number of transforms (1 byte)
    :ivar spi: Security Parameter Index (variable length)
    """

    protocol_id: Ikev1ProtocolId = attr.ib(validator=attr.validators.instance_of(Ikev1ProtocolId))
    transforms: typing.List[Ikev1PayloadTransform] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(Ikev1PayloadTransform),
    ))
    spi: bytes = attr.ib(default=bytes(), converter=bytes, validator=attr.validators.instance_of(bytes))
    next_payload: typing.Optional[Ikev1PayloadType] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(Ikev1PayloadType))
    )
    proposal_number: typing.Optional[int] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.PROPOSAL

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric('proposal_number', 1)
        parser.parse_numeric_enum_coded('protocol_id', Ikev1ProtocolId)
        parser.parse_numeric('spi_size', 1)
        parser.parse_numeric('transform_count', 1)
        parser.parse_raw('spi', parser['spi_size'])

        transforms = []
        for _ in range(parser['transform_count']):
            parser.parse_parsable('transform', Ikev1PayloadTransform)
            transforms.append(parser['transform'])

        payload = cls(
            protocol_id=parser['protocol_id'],
            spi=parser['spi'],
            transforms=transforms,
        )
        payload.next_payload = parser['next_payload']
        payload.proposal_number = parser['proposal_number']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_numeric(self.proposal_number, 1)
        composer_payload.compose_numeric_enum_coded(self.protocol_id)
        composer_payload.compose_numeric(len(self.spi), 1)
        composer_payload.compose_numeric(len(self.transforms), 1)
        composer_payload.compose_raw(self.spi)

        for transform_number, transform in enumerate(self.transforms):
            transform.next_payload = (
                transform.get_payload_type()
                if transform_number < len(self.transforms) - 1
                else Ikev1PayloadType.NONE
            )
            transform.transform_number = transform_number + 1
            composer_payload.compose_parsable(transform)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


class Ikev1Situation(enum.IntFlag):
    """IKEv1 situation."""

    SIT_IDENTITY_ONLY = 1 << 0
    SIT_SECRECY = 1 << 1
    SIT_INTEGRITY = 1 << 2


@attr.s
class Ikev1PayloadSecurityAssociation(Ikev1PayloadBase):
    """Security Association payload parser.

    The Security Association payload has the following format:

    .. code-block:: text

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |    RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |              Domain of Interpretation  (DOI)                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                           Situation                           ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar doi: Domain of Interpretation (4 bytes)
    :ivar situation: Situation field (variable length)
    """

    doi: Ikev1Doi = attr.ib(validator=attr.validators.instance_of(Ikev1Doi))
    situation: typing.List[Ikev1Situation] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(Ikev1Situation),
    ))
    proposals: typing.List[Ikev1PayloadProposal] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(Ikev1PayloadProposal),
    ))

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.SECURITY_ASSOCIATION

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric_enum_coded('doi', Ikev1Doi)
        parser.parse_numeric_flags('situation', 4, Ikev1Situation)

        proposals = []
        parser_proposal = ParserBinary(parsable[parser.parsed_length:parser['payload_length']])
        while parser_proposal.unparsed_length > 0:
            parser_proposal.parse_parsable('proposal', Ikev1PayloadProposal)
            proposal = parser_proposal['proposal']
            proposals.append(proposal)

        payload = cls(
            doi=parser['doi'],
            situation=parser['situation'],
            proposals=proposals
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length + parser_proposal.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_numeric_enum_coded(self.doi)
        composer_payload.compose_numeric_flags(self.situation, 4)

        for proposal_number, proposal in enumerate(self.proposals):
            proposal.next_payload = (
                proposal.get_payload_type()
                if proposal_number < len(self.proposals) - 1
                else Ikev1PayloadType.NONE
            )
            proposal.proposal_number = proposal_number + 1
            composer_payload.compose_parsable(proposal)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadKeyExchange(Ikev1PayloadBase):
    """Key Exchange payload parser.

    The Key Exchange payload has the following format:

    .. code-block:: text

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |    RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                           Key Exchange                          ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar next_payload: Next payload type (1 byte)
    :ivar key_exchange_data: Key exchange data (variable length)
    """

    key_exchange_data: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.KEY_EXCHANGE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_raw('key_exchange_data', parser['payload_length'] - cls.HEADER_SIZE)
        payload = cls(key_exchange_data=parser['key_exchange_data'])
        payload.next_payload = parser['next_payload']
        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.key_exchange_data)
        composer_header = self.compose_header(composer_payload.composed_length)
        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadNonce(Ikev1PayloadBase):
    """Nonce payload parser.

    The Nonce payload has the following format:

    .. code-block:: text

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                           Nonce                               ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar nonce_data: Nonce data (variable length)
    """

    nonce_data: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.NONCE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_raw('nonce_data', parser['payload_length'] - cls.HEADER_SIZE)
        payload = cls(nonce_data=parser['nonce_data'])
        payload.next_payload = parser['next_payload']
        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.nonce_data)
        composer_header = self.compose_header(composer_payload.composed_length)
        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadHash(Ikev1PayloadBase):
    """Hash payload parser.

    The Hash payload has the following format:

    .. code-block:: text

                          1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Next Payload  |   RESERVED    |         Payload Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        ~                           Hash Data                           ~
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar hash_data: Hash data (variable length)
    """

    hash_data: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.HASH

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_raw('hash_data', parser['payload_length'] - cls.HEADER_SIZE)
        payload = cls(hash_data=parser['hash_data'])
        payload.next_payload = parser['next_payload']
        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.hash_data)
        composer_header = self.compose_header(composer_payload.composed_length)
        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadDoiProtocolSpiBase(Ikev1PayloadBase):
    """Base class for IKEv1 payloads with DOI, Protocol-Id, and SPI Size fields.

    Shared structure:

    .. code-block:: text

       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |              Domain of Interpretation  (DOI)                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Protocol-Id  |   SPI Size    |                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar doi: Domain of Interpretation (4 bytes)
    :ivar protocol_id: Protocol ID (1 byte)
    :ivar spi_size: Size of SPI in bytes (1 byte)
    """

    DOI_PROTOCOL_SPI_SIZE = 6

    doi: Ikev1Doi = attr.ib(validator=attr.validators.instance_of(Ikev1Doi))
    protocol_id: Ikev1ProtocolId = attr.ib(validator=attr.validators.instance_of(Ikev1ProtocolId))
    spi_size: int = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = super()._parse_header(parsable)
        if parser.unparsed_length < cls.DOI_PROTOCOL_SPI_SIZE:
            raise NotEnoughData(cls.DOI_PROTOCOL_SPI_SIZE - parser.unparsed_length)

        parser.parse_numeric_enum_coded('doi', Ikev1Doi)
        parser.parse_numeric_enum_coded('protocol_id', Ikev1ProtocolId)
        parser.parse_numeric('spi_size', 1)

        return parser

    def _compose_doi_protocol_spi(self, composer):
        """Compose DOI, Protocol-Id, and SPI Size to composer."""
        composer.compose_numeric_enum_coded(self.doi)
        composer.compose_numeric_enum_coded(self.protocol_id)
        composer.compose_numeric(self.spi_size, 1)


@attr.s
class Ikev1PayloadNotification(Ikev1PayloadDoiProtocolSpiBase):
    """Notification payload parser.

    The Notification payload has the following format:

    .. code-block:: text

                          1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ! Next Payload  !   RESERVED    !         Payload Length        !
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        !              Domain of Interpretation  (DOI)                  !
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        !                                                               !
        ~                Security Parameter Index (SPI)                 ~
        !                                                               !
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        !                                                               !
        ~                       Notification Data                       ~
        !                                                               !
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar notify_message_type: Notify message type (1 byte)
    :ivar spi: Security Parameter Index (variable length)
    :ivar notification_data: Notification data (variable length)
    """

    notify_type: Ikev1NotifyType = attr.ib(validator=attr.validators.instance_of(Ikev1NotifyType))
    spi: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))
    notification_data: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.NOTIFICATION

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_numeric_enum_coded('notify_type', Ikev1NotifyType)
        parser.parse_raw('spi', parser['spi_size'])
        parser.parse_raw('notification_data', parser['payload_length'] - parser.parsed_length)

        payload = cls(
            doi=parser['doi'],
            protocol_id=parser['protocol_id'],
            spi_size=parser['spi_size'],
            notify_type=parser['notify_type'],
            spi=parser['spi'],
            notification_data=parser['notification_data']
        )
        payload.next_payload = parser['next_payload']
        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        self._compose_doi_protocol_spi(composer_payload)
        composer_payload.compose_numeric_enum_coded(self.notify_type)
        composer_payload.compose_raw(self.spi)
        composer_payload.compose_raw(self.notification_data)

        composer_header = self.compose_header(composer_payload.composed_length)
        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadDelete(Ikev1PayloadDoiProtocolSpiBase):
    """Delete payload parser.

    The Delete payload has the following format:

    .. code-block:: text

                          1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |   RESERVED    |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |              Domain of Interpretation  (DOI)                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Protocol-Id  |   SPI Size    |           # of SPIs           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~               Security Parameter Index(es) (SPI)              ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar spis: Security Parameter Index(es) (variable length, list of spi_size bytes each)
    """

    spis: typing.Sequence[typing.Union[bytes, bytearray]] = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of((bytes, bytearray)),
        )
    )

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.DELETE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_numeric('spi_count', 2)

        spis = []
        for _ in range(parser['spi_count']):
            parser.parse_raw('spi', parser['spi_size'])
            spis.append(parser['spi'])

        payload = cls(
            doi=parser['doi'],
            protocol_id=parser['protocol_id'],
            spi_size=parser['spi_size'],
            spis=spis,
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        self._compose_doi_protocol_spi(composer_payload)
        composer_payload.compose_numeric(len(self.spis), 2)

        for spi in self.spis:
            composer_payload.compose_raw(spi)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadVendorId(Ikev1PayloadBase):
    """Vendor ID payload parser.

    The Vendor ID payload has the following format:

    .. code-block:: text

       1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                        Vendor ID (VID)                        ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar vendor_id: Vendor ID (variable length)
    """

    vendor_id: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.VENDOR_ID

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_raw('vendor_id', parser['payload_length'] - cls.HEADER_SIZE)

        payload = cls(vendor_id=parser['vendor_id'])
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()

        composer_payload.compose_raw(self.vendor_id)
        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev1PayloadCertificateRequest(Ikev1PayloadBase):
    """Certificate Request payload parser.

    The Certificate Request payload has the following format:

    .. code-block:: text

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Next Payload  |C|  RESERVED   |         Payload Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Cert Encoding |                                               |
        +-+-+-+-+-+-+-+-+                                               +
        ~                       Certificate Data                        ~
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar cert_encoding: Certificate encoding type
    :ivar certificate_data: Certificate data
    """

    cert_encoding: int = attr.ib(validator=attr.validators.instance_of(int))
    certificate_data: typing.Union[bytes, bytearray] = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray))
    )

    @classmethod
    def get_payload_type(cls):
        return Ikev1PayloadType.CERTIFICATE_REQUEST

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_numeric('cert_encoding', 1)
        parser.parse_raw('certificate_data', parser['payload_length'] - cls.HEADER_SIZE - 1)

        payload = cls(
            cert_encoding=parser['cert_encoding'],
            certificate_data=parser['certificate_data']
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_numeric(self.cert_encoding, 1)
        composer_payload.compose_raw(self.certificate_data)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


IKEV1_PAYLOAD_CLASSES_BY_TYPE = {
    Ikev1PayloadType.SECURITY_ASSOCIATION: Ikev1PayloadSecurityAssociation,
    Ikev1PayloadType.KEY_EXCHANGE: Ikev1PayloadKeyExchange,
    Ikev1PayloadType.HASH: Ikev1PayloadHash,
    Ikev1PayloadType.NONCE: Ikev1PayloadNonce,
    Ikev1PayloadType.NOTIFICATION: Ikev1PayloadNotification,
    Ikev1PayloadType.DELETE: Ikev1PayloadDelete,
    Ikev1PayloadType.VENDOR_ID: Ikev1PayloadVendorId,
    Ikev1PayloadType.CERTIFICATE_REQUEST: Ikev1PayloadCertificateRequest,
}


class Ikev1AttributeVariantBase(VariantParsable):
    @classmethod
    @abc.abstractmethod
    def get_parsed_extensions(cls):
        raise NotImplementedError()

    @classmethod
    def _get_variants(cls):
        variants = cls.get_parsed_extensions()

        # variants.update([
        #     (extension_type, (Ikev1AttributeUnparsed, ))
        #     for extension_type in Ikev1AttributeType
        #     if extension_type not in variants
        # ])

        return variants


class Ikev1AttributeVariantServer(Ikev1AttributeVariantBase):
    @classmethod
    def get_parsed_extensions(cls):
        return collections.OrderedDict([
            (Ikev1AttributeType.ENCRYPTION_ALGORITHM, [Ikev1AttributeEncryptionAlgorithm, ]),
            (Ikev1AttributeType.HASH_ALGORITHM, [Ikev1AttributeHashAlgorithm, ]),
            (Ikev1AttributeType.LIFE_TYPE, [Ikev1AttributeLifeType, ]),
            (Ikev1AttributeType.KEY_LENGTH, [Ikev1AttributeKeyLength, ]),
            (Ikev1AttributeType.GROUP_DESCRIPTION, [Ikev1AttributeDiffieHellmanGroup, ]),
            (Ikev1AttributeType.AUTHENTICATION_METHOD, [Ikev1AttributeAuthenticationMethod, ]),
            (Ikev1AttributeType.LIFE_DURATION, [Ikev1AttributeLifeDuration, ]),
        ])
