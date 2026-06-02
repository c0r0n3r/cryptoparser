# SPDX-License-Identifier: MPL-2.0
"""ISAKMP version handling."""

import abc

import attr

from cryptodatahub.common.grade import GradeableSimple, Grade
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.common.base import OneByteEnumParsable


class IsakmpVersionFactory(OneByteEnumParsable):
    """ISAKMP version."""
    @classmethod
    def get_enum_class(cls):
        return IkeVersion

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s(frozen=True, order=False)
class IsakmpProtocolVersion(ParsableBase, GradeableSimple):
    """ISAKMP protocol version parser."""
    HEADER_SIZE = 1

    major = attr.ib(validator=attr.validators.instance_of(IkeVersion))
    minor: int = attr.ib(validator=attr.validators.instance_of(int))

    def __lt__(self, other):
        if self.major.value.code != other.major.value.code:
            return self.major.value.code < other.major.value.code
        return self.minor < other.minor

    @property
    def grade(self):
        if self.major == IkeVersion.V1:
            return Grade.DEPRECATED

        return Grade.SECURE

    def __str__(self):
        return f"IKEv{self.major.value.code} ({self.minor})"

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_numeric('version', 1)

        major_version = (parser['version'] >> 4) & 0x0f
        minor_version = parser['version'] & 0x0f

        if major_version not in [v.value.code for v in IkeVersion]:
            raise InvalidType()

        return cls(
            major=next(v for v in IkeVersion if v.value.code == major_version),
            minor=minor_version,
        ), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        version = (self.major.value.code << 4) | self.minor
        composer.compose_numeric(version, 1)

        return composer.composed_bytes

    @property
    def version(self):
        """Get version as string."""
        return f"{self.major.value.code}.{self.minor}"
