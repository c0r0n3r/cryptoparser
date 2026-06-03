# SPDX-License-Identifier: MPL-2.0
"""IKEv2 message parsers."""
# pylint: disable=too-many-lines

import abc
import collections
import enum
import typing

import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    Ikev2TransformAttributeType,
    Ikev2PayloadType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
    Ikev2TransformType,
)
from cryptoparser.common.base import TwoByteEnumParsable, VariantParsable
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidType
from cryptoparser.ike.common import DataAttributeLength, DataAttributeTypeValue, DataAttributeFormat


class Ikev2ProposalFlags(enum.IntFlag):
    """Proposal flags."""
    LAST_SUBSTRUCT = 0x80


class Ikev2PayloadFlags(enum.IntFlag):
    """Payload flags."""
    CRITICAL = 0x80  # Critical bit flag


@attr.s
class Ikev2PayloadBase(ParsableBase):
    """Payload header parser, according to RFC7296.

    The generic payload header has the following structure:

    .. code-block:: text

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Next Payload  |C|  RESERVED   |         Payload Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :cvar HEADER_SIZE: Size of the header in bytes
    :ivar next_payload: Type of the next payload (1 byte)
    :ivar critical: Critical bit flag (1 bit)
    """
    HEADER_SIZE = 4

    flags: set[Ikev2PayloadFlags] = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(Ikev2PayloadFlags),
        )
    )
    next_payload: typing.Optional[Ikev2PayloadType] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(Ikev2PayloadType))
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
        parser.parse_numeric_enum_coded('next_payload', Ikev2PayloadType)
        parser.parse_numeric_flags('flags', 1, Ikev2PayloadFlags)
        parser.parse_numeric('payload_length', 2)

        if parser.unparsed_length < parser['payload_length'] - cls.HEADER_SIZE:
            raise NotEnoughData(parser['payload_length'] - cls.HEADER_SIZE - parser.unparsed_length)

        return parser

    def compose_header(self, payload_length):
        """Compose payload header to bytes.

        :return: Composed header bytes
        :rtype: bytes
        """
        assert self.next_payload is not None

        composer = ComposerBinary()
        composer.compose_numeric(self.next_payload.value.code, 1)
        composer.compose_numeric_flags(self.flags, 1)
        composer.compose_numeric(self.HEADER_SIZE + payload_length, 2)

        return composer


class TransformNextPayload(enum.IntEnum):
    """Transform next payload."""
    LAST = 0x00
    MORE = 0x03


@attr.s
class Transform(ParsableBase):
    """Transform payload parser.

    The transform payload has the following format:

    .. code-block:: text

                             1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Next payload  |   RESERVED    |        Transform Length       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Transform Type |   RESERVED    |          Transform ID         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        ~                      Transform Attributes                     ~
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar transform_id: Transform ID
    :ivar next_payload: Next payload
    """
    HEADER_SIZE = 8

    transform_id: typing.Any = attr.ib()
    next_payload: typing.Optional[TransformNextPayload] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(TransformNextPayload))
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
    def get_transform_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_transform_id_class(cls):
        raise NotImplementedError()

    @transform_id.validator
    def _validate_transform_id(self, _, value):
        transform_id_class = self._get_transform_id_class()
        if not isinstance(value, transform_id_class):
            raise InvalidValue(value, type(self), 'value')

    @classmethod
    def _parse_header(cls, parsable):
        """Parse transform from bytes.

        :param parsable: Bytes to parse
        :type parsable: bytes
        :return: Tuple of (parsed transform, number of bytes parsed)
        :rtype: tuple(Transform, int)
        :raises NotEnoughData: If there are not enough bytes to parse
        """
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_numeric('next_payload', 1, TransformNextPayload)
        parser.parse_numeric('reserved', 1)
        parser.parse_numeric('transform_length', 2)
        parser.parse_numeric_enum_coded('transform_type', Ikev2TransformType)

        if parser['transform_type'] != cls.get_transform_type():
            raise InvalidType()

        parser.parse_numeric('reserved2', 1)
        parser.parse_numeric_enum_coded('transform_id', cls._get_transform_id_class())

        return parser

    def compose_header(self, transform_length):
        """Compose transform to bytes.

        :param last_substruc: Whether this is the last substructure
        :type last_substruc: bool
        :return: Composed transform bytes
        :rtype: bytes
        """
        assert self.next_payload is not None

        composer = ComposerBinary()
        composer.compose_numeric(self.next_payload.value, 1)
        composer.compose_numeric(0, 1)  # reserved
        composer.compose_numeric(transform_length + self.HEADER_SIZE, 2)
        composer.compose_numeric(self.get_transform_type().value.code, 1)
        composer.compose_numeric(0, 1)  # reserved2
        composer.compose_numeric(self.transform_id.value.code, 2)

        return composer


class TransformAttributeKeyLength(DataAttributeLength):
    @classmethod
    def get_type(cls):
        return Ikev2TransformAttributeType.KEY_LENGTH

    @classmethod
    def _get_size(cls):
        return 2


@attr.s
class TransformAttributeSignatureAlgorithm(DataAttributeTypeValue):
    """Signature Algorithm transform attribute (TLV format).

    The Signature Algorithm attribute has the following format:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |A|       Attribute Type        |    Attribute Length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                   Signature Algorithm Value                   ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar signature_algorithm: Signature algorithm value
    """
    signature_algorithm: typing.Union[bytearray, bytes] = attr.ib(
        validator=attr.validators.instance_of((bytearray, bytes))
    )

    @classmethod
    def get_type(cls):
        return Ikev2TransformAttributeType.SIGNATURE_ALGORITHM

    @classmethod
    def _get_format(cls):
        return DataAttributeFormat.TYPE_LENGTH_VALUE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        if parser.unparsed_length < 2:
            raise NotEnoughData(2 - parser.unparsed_length)

        parser.parse_numeric('length', 2)
        parser.parse_raw('signature_algorithm', parser['length'])

        return cls(signature_algorithm=bytes(parser['signature_algorithm'])), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(len(self.signature_algorithm), 2)
        composer.compose_raw(self.signature_algorithm)

        return composer.composed_bytes


@attr.s
class TransformNoAttributes(Transform):
    """Transform payload parser for transforms with no attributes."""
    @classmethod
    @abc.abstractmethod
    def get_transform_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_transform_id_class(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        transform = cls(
            transform_id=parser['transform_id'],
        )
        transform.next_payload = parser['next_payload']

        return transform, parser.parsed_length

    def compose(self):
        return self.compose_header(transform_length=0).composed_bytes


@attr.s
class TransformAttributes(Transform):
    """Transform payload parser for transforms with some attributes."""

    @classmethod
    @abc.abstractmethod
    def get_transform_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_transform_id_class(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_attributes(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def _get_attributes(self):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)
        attributes_size = header_parser['transform_length'] - cls.HEADER_SIZE
        attributes, attributes_length = cls._parse_attributes(header_parser.unparsed[:attributes_size])

        transform = cls(
            transform_id=header_parser['transform_id'],
            **attributes
        )

        transform.next_payload = header_parser['next_payload']

        return transform, header_parser.parsed_length + attributes_length

    def compose(self):
        payload_composer = ComposerBinary()
        for attribute in self._get_attributes():
            payload_composer.compose_parsable(attribute)

        header_composer = self.compose_header(transform_length=payload_composer.composed_length)

        return header_composer.composed_bytes + payload_composer.composed_bytes


class Ikev2TransformIntegrity(TransformNoAttributes):
    """Transform payload parser for integrity algorithm."""

    @classmethod
    def get_transform_type(cls):
        return Ikev2TransformType.INTEG

    @classmethod
    def _get_transform_id_class(cls):
        return Ikev2IntegrityAlgorithm


class Ikev2TransformPrf(TransformNoAttributes):
    """Transform payload parser for pseudorandom function."""

    @classmethod
    def get_transform_type(cls):
        return Ikev2TransformType.PRF

    @classmethod
    def _get_transform_id_class(cls):
        return Ikev2PseudorandomFunction


class Ikev2TransformDhGroup(TransformNoAttributes):
    """Transform payload parser for Diffie-Hellman group."""

    @classmethod
    def get_transform_type(cls):
        return Ikev2TransformType.DH

    @classmethod
    def _get_transform_id_class(cls):
        return Ikev2DiffieHellmanGroup


@attr.s
class Ikev2TransformEncryptionAlgorithm(TransformAttributes):
    """Transform payload parser for encryption algorithm."""

    key_length: typing.Optional[int] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )

    @classmethod
    def get_transform_type(cls):
        return Ikev2TransformType.ENCR

    @classmethod
    def _get_transform_id_class(cls):
        return Ikev2EncryptionAlgorithm

    @classmethod
    def _parse_attributes(cls, parsable):
        if not parsable:
            return {'key_length': None}, 0
        parser = ParserBinary(parsable)

        parser.parse_parsable('key_length', TransformAttributeKeyLength)

        return {'key_length': parser['key_length'].value}, parser.parsed_length

    def _get_attributes(self):
        if self.key_length is None:
            return []
        return [TransformAttributeKeyLength(value=self.key_length)]


class Ikev2ProposalNextPayload(enum.IntEnum):
    """Proposal next payload."""
    LAST = 0x00
    MORE = 0x02


@attr.s
class Ikev2Proposal(ParsableBase):
    """Proposal payload parser.

    The proposal payload has the following format:

    .. code-block:: text

                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Last Substruc |   RESERVED    |         Proposal Length       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                        SPI (variable)                         ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                        <Transforms>                           ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar flags: Proposal flags (Ikev2ProposalFlags)
    :ivar protocol_id: Protocol ID
    :ivar spi: Security Parameter Index
    :ivar transforms: List of transforms
    """
    HEADER_SIZE = 8

    protocol_id: Ikev2ProtocolId = attr.ib(validator=attr.validators.instance_of(Ikev2ProtocolId))
    transforms: list[Transform] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(Transform)
    ))
    spi: bytes = attr.ib(default=b'', converter=bytes, validator=attr.validators.instance_of(bytes))
    last: typing.Optional[Ikev2ProposalNextPayload] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(Ikev2ProposalNextPayload))
    )
    proposal_number: typing.Optional[int] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )

    @classmethod
    def _parse(cls, parsable):
        """Parse proposal from bytes.

        :param parsable: Bytes to parse
        :type parsable: bytes
        :return: Tuple of (parsed proposal, number of bytes parsed)
        :rtype: tuple(Ikev2ProposalPayload, int)
        :raises NotEnoughData: If there are not enough bytes to parse
        """
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_numeric_flags('last', 1, Ikev2ProposalNextPayload)
        parser.parse_numeric('reserved', 1)
        parser.parse_numeric('proposal_length', 2)
        parser.parse_numeric('proposal_number', 1)
        parser.parse_numeric_enum_coded('protocol_id', Ikev2ProtocolId)
        parser.parse_numeric('spi_size', 1)
        parser.parse_numeric('transform_count', 1)
        parser.parse_raw('spi', parser['spi_size'])

        transforms = []
        for _ in range(parser['transform_count']):
            parser.parse_parsable('transform', Ikev2TransformVariantInitiator)
            transforms.append(parser['transform'])

        proposal = cls(
            protocol_id=parser['protocol_id'],
            spi=parser['spi'],
            transforms=transforms
        )

        proposal.last = parser['last']
        proposal.proposal_number = parser['proposal_number']

        return proposal, parser.parsed_length

    def compose(self):
        """Compose proposal to bytes.

        :param last_substruc: Whether this is the last substructure
        :type last_substruc: bool
        :return: Composed proposal bytes
        :rtype: bytes
        """
        assert self.last is not None

        header_composer = ComposerBinary()
        header_composer.compose_numeric(self.last.value, 1)
        header_composer.compose_numeric(0, 1)  # reserved

        payload_composer = ComposerBinary()
        for i, transform in enumerate(self.transforms):
            transform.next_payload = (
                TransformNextPayload.MORE
                if i < len(self.transforms) - 1
                else TransformNextPayload.LAST
            )
            payload_composer.compose_parsable(transform)

        header_composer.compose_numeric(self.HEADER_SIZE + len(payload_composer.composed_bytes), 2)
        header_composer.compose_numeric(self.proposal_number, 1)
        header_composer.compose_numeric(self.protocol_id.value.code, 1)
        header_composer.compose_numeric(len(self.spi), 1)
        header_composer.compose_numeric(len(self.transforms), 1)
        if self.spi:
            header_composer.compose_raw(self.spi)

        return header_composer.composed_bytes + payload_composer.composed_bytes


@attr.s
class Ikev2PayloadSecurityAssociation(Ikev2PayloadBase):
    """Security Association payload parser.

    The Security Association payload has the following format:

    .. code-block:: text
                        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                          <Proposals>                          ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    proposals: list[Ikev2Proposal] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(Ikev2Proposal)
    ))

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.SA

    def get_transform_by_type(self, transform_type: Ikev2TransformType) -> Transform:
        for proposal in self.proposals:
            for transform in proposal.transforms:
                if transform.get_transform_type() == transform_type:
                    return transform

        raise KeyError(transform_type)

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        proposals = []
        parser_proposal = ParserBinary(parser.unparsed[:parser['payload_length'] - cls.HEADER_SIZE:])
        while parser_proposal.unparsed_length > 0:
            parser_proposal.parse_parsable('proposal', Ikev2Proposal)
            proposal = parser_proposal['proposal']
            proposals.append(proposal)

        payload = cls(
            flags=parser['flags'],
            proposals=proposals
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length + parser_proposal.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()

        for proposal_number, proposal in enumerate(self.proposals):
            proposal.last = (
                Ikev2ProposalNextPayload.MORE
                if proposal_number < len(self.proposals) - 1
                else Ikev2ProposalNextPayload.LAST
            )
            proposal.proposal_number = proposal_number + 1
            composer_payload.compose_parsable(proposal)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev2PayloadNonce(Ikev2PayloadBase):
    """Nonce payload parser.

    The nonce payload has the following format:

    .. code-block:: text
                        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                            Nonce Data                         ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar nonce_data: Random data generated by the transmitting entity
    """
    nonce_data: bytes = attr.ib(
        converter=bytes,
        validator=attr.validators.and_(
            attr.validators.instance_of(bytes),
            attr.validators.min_len(16),
            attr.validators.max_len(256)
        )
    )

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.NONCE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        nonce_data_length = parser['payload_length'] - cls.HEADER_SIZE

        if nonce_data_length < 16:
            raise NotEnoughData(bytes_needed=16 - nonce_data_length)
        if nonce_data_length > 256:
            raise TooMuchData(bytes_needed=nonce_data_length - 256)

        parser.parse_raw('nonce_data', nonce_data_length)

        payload = cls(
            flags=parser['flags'],
            nonce_data=parser['nonce_data']
        )
        payload.next_payload = parser['next_payload']
        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.nonce_data)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev2PayloadKeyExchange(Ikev2PayloadBase):
    """Key exchange payload parser.

    The key exchange payload has the following format:

    .. code-block:: text
                        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Diffie-Hellman Group Num    |           RESERVED            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                       Key Exchange Data                       ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar dh_group: Diffie-Hellman group number
    :ivar key_exchange_data: Diffie-Hellman public value
    """
    dh_group: Ikev2DiffieHellmanGroup = attr.ib(validator=attr.validators.instance_of(Ikev2DiffieHellmanGroup))
    key_exchange_data: typing.Union[bytes, bytearray] = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray))
    )

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.KE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_numeric_enum_coded('dh_group', Ikev2DiffieHellmanGroup)
        parser.parse_numeric('reserved2', 2)

        key_exchange_length = parser['payload_length'] - 8
        parser.parse_raw('key_exchange_data', key_exchange_length)

        payload = cls(
            flags=parser['flags'],
            dh_group=parser['dh_group'],
            key_exchange_data=parser['key_exchange_data']
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_numeric(self.dh_group.value.code, 2)
        composer_payload.compose_numeric(0, 2)  # reserved2
        composer_payload.compose_raw(self.key_exchange_data)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


@attr.s
class Ikev2PayloadDelete(Ikev2PayloadBase):
    """Delete payload parser.

    The Delete payload has the following format:

    .. code-block:: text
                        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Protocol ID   |   SPI Size    |          Num of SPIs          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~               Security Parameter Index(es) (SPI)              ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar protocol_id: Protocol ID
    :ivar spi_size: Length in octets of the SPI
    :ivar num_spis: Number of SPIs contained in the payload
    :ivar spis: List of Security Parameter Indexes
    """
    protocol_id: Ikev2ProtocolId = attr.ib(validator=attr.validators.instance_of(Ikev2ProtocolId))
    spis: list[int] = attr.ib(validator=attr.validators.deep_iterable(
        member_validator=attr.validators.instance_of(int),
    ))

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.DELETE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric_enum_coded('protocol_id', Ikev2ProtocolId)
        parser.parse_numeric('spi_size', 1)
        parser.parse_numeric('num_spis', 2)

        parser.parse_numeric_array('spis', parser['num_spis'], 8)
        payload = cls(
            flags=parser['flags'],
            protocol_id=parser['protocol_id'],
            spis=parser['spis']
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_numeric_enum_coded(self.protocol_id)
        composer_payload.compose_numeric(len(self.spis) * 8, 1)
        composer_payload.compose_numeric(len(self.spis), 2)

        composer_payload.compose_numeric_array(self.spis, 8)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


class Ikev2NotifyTypeFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return Ikev2NotifyType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class Ikev2PayloadNotifyBase(Ikev2PayloadBase):
    """Notify payload parser.

    The notify payload has the following format:

    .. code-block:: text
                         1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Next Payload  |C|  RESERVED   |         Payload Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Protocol ID  |   SPI Size    |      Notify Message Type      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        ~                Security Parameter Index (SPI)                 ~
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        ~                       Notification Data                       ~
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar protocol_id: Protocol ID (1 byte)
    :ivar spi_size: Size of SPI in bytes (1 byte)
    :ivar notify_message_type: Type of notification message (2 bytes)
    :ivar spi: Security Parameter Index (variable length)
    :ivar data: Notification data (variable length)
    """
    protocol_id: Ikev2ProtocolId = attr.ib(validator=attr.validators.instance_of(Ikev2ProtocolId))
    type: Ikev2NotifyType = attr.ib(validator=attr.validators.instance_of(Ikev2NotifyType))
    spi: bytes = attr.ib(converter=bytes, validator=attr.validators.instance_of(bytes))

    @classmethod
    @abc.abstractmethod
    def _parse_type(cls, parser, name):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_data(cls, parser, notification_data_length):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_data(self, composer):
        raise NotImplementedError()

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.NOTIFY

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric_enum_coded('protocol_id', Ikev2ProtocolId)
        parser.parse_numeric('spi_size', 1)
        cls._parse_type(parser, 'type')

        if parser['spi_size'] > 0:
            parser.parse_raw('spi', parser['spi_size'])
            spi = parser['spi']
        else:
            spi = b''

        del parser['spi_size']
        if 'spi' in parser:
            del parser['spi']

        notification_data_length = parser['payload_length'] - (cls.HEADER_SIZE + 4) - len(spi)

        cls._parse_data(parser, notification_data_length)

        next_payload = parser['next_payload']
        del parser['next_payload']
        del parser['payload_length']
        payload = cls(
            **parser,
            spi=spi,
        )
        payload.next_payload = next_payload

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()

        composer_payload.compose_numeric_enum_coded(self.protocol_id)
        composer_payload.compose_numeric(len(self.spi), 1)
        composer_payload.compose_numeric_enum_coded(self.type)

        if self.spi:
            composer_payload.compose_raw(self.spi)

        self._compose_data(composer_payload)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


class Ikev2PayloadNotifyNoData(Ikev2PayloadNotifyBase):
    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        pass

    def _compose_data(self, composer):
        pass

    @classmethod
    @abc.abstractmethod
    def _get_message_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_type(cls, parser, name):
        parser.parse_parsable(name, Ikev2NotifyTypeFactory)

        if parser[name] != cls._get_message_type():
            raise InvalidType()


class Ikev2PayloadNotifyAuthenticationFailed(Ikev2PayloadNotifyNoData):
    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.AUTHENTICATION_FAILED


class Ikev2NotifyPayloadUseTransportMode(Ikev2PayloadNotifyNoData):
    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.USE_TRANSPORT_MODE


class Ikev2NotifyPayloadHttpCertLookupSupported(Ikev2PayloadNotifyNoData):
    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.HTTP_CERT_LOOKUP_SUPPORTED


class Ikev2NotifyPayloadIntermediateExchangeSupported(Ikev2PayloadNotifyNoData):
    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.INTERMEDIATE_EXCHANGE_SUPPORTED


class Ikev2NotifyPayloadUsePpk(Ikev2PayloadNotifyNoData):
    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.USE_PPK


class Ikev2NotifyPayloadRedirectSupported(Ikev2PayloadNotifyNoData):
    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.REDIRECT_SUPPORTED


@attr.s
class Ikev2PayloadNotifyUnparsed(Ikev2PayloadNotifyBase):
    data: typing.Union[bytes, bytearray] = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        parser.parse_raw('data', notification_data_length)

    def _compose_data(self, composer):
        composer.compose_raw(self.data)

    @classmethod
    def _parse_type(cls, parser, name):
        parser.parse_numeric_enum_coded(name, Ikev2NotifyType)


@attr.s
class Ikev2PayloadNotifyParsedBase(Ikev2PayloadNotifyBase):
    @classmethod
    @abc.abstractmethod
    def _parse_data(cls, parser, notification_data_length):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_data(self, composer):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_message_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_type(cls, parser, name):
        parser.parse_numeric_enum_coded(name, Ikev2NotifyType)

        if parser[name] != cls._get_message_type():
            raise InvalidType()


@attr.s
class Ikev2NotifyPayloadInvalidKe(Ikev2PayloadNotifyParsedBase):
    """Invalid KE payload notification data parser."""
    dh_group: Ikev2DiffieHellmanGroup = attr.ib(validator=attr.validators.instance_of(Ikev2DiffieHellmanGroup))

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.INVALID_KE_PAYLOAD

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        parser.parse_numeric_enum_coded('dh_group', Ikev2DiffieHellmanGroup)

    def _compose_data(self, composer):
        composer.compose_numeric_enum_coded(self.dh_group)


@attr.s
class Ikev2NotifyPayloadCookie(Ikev2PayloadNotifyParsedBase):
    """Invalid KE payload notification data parser."""
    cookie: typing.Union[bytes, bytearray] = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.COOKIE

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        parser.parse_raw('cookie', notification_data_length)

    def _compose_data(self, composer):
        composer.compose_raw(self.cookie)


@attr.s
class Ikev2NotifyPayloadSetWindowSize(Ikev2PayloadNotifyParsedBase):
    """Set window size payload notification data parser."""
    window_size: int = attr.ib(validator=[
        attr.validators.instance_of(int),
        attr.validators.in_(range(0, 2 ** 32)),
    ])

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.SET_WINDOW_SIZE

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        if notification_data_length != 4:
            raise InvalidValue(notification_data_length, cls, 'notification_data_length')
        parser.parse_numeric('window_size', 4)

    def _compose_data(self, composer):
        composer.compose_numeric(self.window_size, 4)


@attr.s
class Ikev2NotifyPayloadNatDetectionBase(Ikev2PayloadNotifyParsedBase):
    hash_data: typing.Union[bytes, bytearray] = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    @abc.abstractmethod
    def _get_message_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        parser.parse_raw('hash_data', notification_data_length)

    def _compose_data(self, composer):
        composer.compose_raw(self.hash_data)


@attr.s
class Ikev2NotifyPayloadNatDetectionSourceIp(Ikev2NotifyPayloadNatDetectionBase):
    """NAT detection source IP payload notification data parser."""

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.NAT_DETECTION_SOURCE_IP


@attr.s
class Ikev2NotifyPayloadNatDetectionDestinationIp(Ikev2NotifyPayloadNatDetectionBase):
    """NAT detection destination IP payload notification data parser."""

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.NAT_DETECTION_DESTINATION_IP


@attr.s
class Ikev2NotifyPayloadSignatureHashAlgorithms(Ikev2PayloadNotifyParsedBase):
    """Signature hash algorithms notification (RFC 7427 §4)."""
    hash_algorithms: tuple[int, ...] = attr.ib(
        converter=tuple,
        validator=attr.validators.deep_iterable(attr.validators.instance_of(int)),
    )

    @classmethod
    def _get_message_type(cls):
        return Ikev2NotifyType.SIGNATURE_HASH_ALGORITHMS

    @classmethod
    def _parse_data(cls, parser, notification_data_length):
        if notification_data_length % 2 != 0:
            raise InvalidValue(notification_data_length, cls, 'notification_data_length')
        parser.parse_numeric_array('hash_algorithms', notification_data_length // 2, 2)

    def _compose_data(self, composer):
        for hash_id in self.hash_algorithms:
            composer.compose_numeric(hash_id, 2)


class Ikev2NotifyPayloadVariantBase(VariantParsable):
    @classmethod
    @abc.abstractmethod
    def get_parsed_notifies(cls):
        raise NotImplementedError()

    @classmethod
    def _get_variants(cls):
        variants = cls.get_parsed_notifies()

        variants.update([
            (notify_type, (Ikev2PayloadNotifyUnparsed, ))
            for notify_type in Ikev2NotifyType
            if notify_type not in variants
        ])

        return variants


class Ikev2NotifyPayloadVariantResponder(Ikev2NotifyPayloadVariantBase):
    @classmethod
    def get_parsed_notifies(cls):
        return collections.OrderedDict([
            (Ikev2NotifyType.COOKIE, [Ikev2NotifyPayloadCookie, ]),
            (Ikev2NotifyType.INVALID_KE_PAYLOAD, [Ikev2NotifyPayloadInvalidKe, ]),
            (Ikev2NotifyType.SET_WINDOW_SIZE, [Ikev2NotifyPayloadSetWindowSize, ]),
            (Ikev2NotifyType.NAT_DETECTION_SOURCE_IP, [Ikev2NotifyPayloadNatDetectionSourceIp, ]),
            (Ikev2NotifyType.NAT_DETECTION_DESTINATION_IP, [Ikev2NotifyPayloadNatDetectionDestinationIp, ]),
            (Ikev2NotifyType.USE_TRANSPORT_MODE, [Ikev2NotifyPayloadUseTransportMode, ]),
            (Ikev2NotifyType.HTTP_CERT_LOOKUP_SUPPORTED, [Ikev2NotifyPayloadHttpCertLookupSupported, ]),
            (Ikev2NotifyType.SIGNATURE_HASH_ALGORITHMS, [Ikev2NotifyPayloadSignatureHashAlgorithms, ]),
            (Ikev2NotifyType.INTERMEDIATE_EXCHANGE_SUPPORTED, [Ikev2NotifyPayloadIntermediateExchangeSupported, ]),
            (Ikev2NotifyType.USE_PPK, [Ikev2NotifyPayloadUsePpk, ]),
            (Ikev2NotifyType.REDIRECT_SUPPORTED, [Ikev2NotifyPayloadRedirectSupported, ]),
        ])


@attr.s
class Ikev2PayloadCertificateRequest(Ikev2PayloadBase):
    """Certificate Request payload parser.

    The Certificate Request payload has the following format:

    .. code-block:: text
                        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Cert Encoding |                                               |
       +-+-+-+-+-+-+-+-+                                               |
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
        return Ikev2PayloadType.CERTREQ

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_numeric('cert_encoding', 1)
        parser.parse_raw('certificate_data', parser['payload_length'] - cls.HEADER_SIZE - 1)

        payload = cls(
            flags=parser['flags'],
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


@attr.s
class Ikev2PayloadVendorId(Ikev2PayloadBase):
    """Vendor ID payload parser.

    The Vendor ID payload has the following format:

    .. code-block:: text
                        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Payload  |C|  RESERVED   |         Payload Length        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       ~                        Vendor ID (VID)                        ~
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar vendor_id: Vendor ID data
    """
    vendor_id: typing.Union[bytes, bytearray] = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def get_payload_type(cls):
        return Ikev2PayloadType.VENDOR_ID

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_raw('vendor_id', parser['payload_length'] - cls.HEADER_SIZE)

        payload = cls(
            flags=parser['flags'],
            vendor_id=parser['vendor_id']
        )
        payload.next_payload = parser['next_payload']

        return payload, parser.parsed_length

    def compose(self):
        composer_payload = ComposerBinary()
        composer_payload.compose_raw(self.vendor_id)

        composer_header = self.compose_header(composer_payload.composed_length)

        return composer_header.composed_bytes + composer_payload.composed_bytes


IKEV2_PAYLOAD_CLASSES_BY_TYPE = {
    Ikev2PayloadType.SA: Ikev2PayloadSecurityAssociation,
    Ikev2PayloadType.NONCE: Ikev2PayloadNonce,
    Ikev2PayloadType.KE: Ikev2PayloadKeyExchange,
    Ikev2PayloadType.NOTIFY: Ikev2NotifyPayloadVariantResponder,
    Ikev2PayloadType.CERTREQ: Ikev2PayloadCertificateRequest,
    Ikev2PayloadType.VENDOR_ID: Ikev2PayloadVendorId,
}


class Ikev2TransformVariantBase(VariantParsable):
    @classmethod
    @abc.abstractmethod
    def get_parsed_transforms(cls):
        raise NotImplementedError()

    @classmethod
    def _get_variants(cls):
        variants = cls.get_parsed_transforms()

        variants.update([
            (Ikev2TransformType.ENCR, [Ikev2TransformEncryptionAlgorithm, ]),
            (Ikev2TransformType.PRF, [Ikev2TransformPrf, ]),
            (Ikev2TransformType.DH, [Ikev2TransformDhGroup, ]),
            (Ikev2TransformType.INTEG, [Ikev2TransformIntegrity, ]),
        ])

        return variants


class Ikev2TransformVariantInitiator(Ikev2TransformVariantBase):
    @classmethod
    def get_parsed_transforms(cls):
        return collections.OrderedDict()
