"""ISAKMP version handling."""

import abc
import enum

import attr

from cryptodatahub.common.grade import GradeableSimple, Grade

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.common.base import OneByteEnumParsable


class IsakmpVersion(enum.IntEnum):
    """ISAKMP version."""
    V1 = 0x01  # ISAKMP v1
    V2 = 0x02  # ISAKMP v2 (IKEv2)

    @property
    def identifier(self):
        """Get version identifier."""
        return f"ikev{self.value}"


class IsakmpVersionFactory(OneByteEnumParsable):
    """ISAKMP version."""
    @classmethod
    def get_enum_class(cls):
        return IsakmpVersion

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s(frozen=True)
class IsakmpProtocolVersion(ParsableBase, GradeableSimple):
    """ISAKMP protocol version parser."""
    HEADER_SIZE = 1

    major: IsakmpVersion = attr.ib(validator=attr.validators.instance_of(IsakmpVersion))
    minor: int = attr.ib(validator=attr.validators.instance_of(int))

    @property
    def grade(self):
        if self.major == IsakmpVersion.V1:
            return Grade.DEPRECATED

        return Grade.SECURE

    def __str__(self):
        return f"IKEv{self.major.value} ({self.minor})"

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_numeric('version', 1)

        major_version = (parser['version'] >> 4) & 0x0f
        minor_version = parser['version'] & 0x0f

        if major_version not in [v.value for v in IsakmpVersion]:
            raise InvalidType()

        return cls(
            major=IsakmpVersion(major_version),
            minor=minor_version,
        ), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        version = (self.major.value << 4) | self.minor
        composer.compose_numeric(version, 1)

        return composer.composed_bytes

    @property
    def version(self):
        """Get version as string."""
        return f"{self.major.value}.{self.minor}"
