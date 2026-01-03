import abc
import enum
import typing

import attr

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import InvalidType
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary


@attr.s
class DataAttributeBase(ParsableBase):
    """Data attribute base parser.

    .. code-block:: text

                              1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         !A!       Attribute Type        !    AF=0  Attribute Length     !
         !F!                             !    AF=1  Attribute Value      !
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         .                   AF=0  Attribute Value                       .
         .                   AF=1  Not Transmitted                       .
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _get_format(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('format', 1, DataAttributeFormat)
        if parser['format'] != cls._get_format():
            raise InvalidType()

        parser.parse_numeric_enum_coded('type', type(cls.get_type()))
        if parser['type'] != cls.get_type():
            raise InvalidType()

        return parser

    def _compose_header(self):
        composer = ComposerBinary()

        composer.compose_numeric(self._get_format().value, 1)
        composer.compose_numeric_enum_coded(self.get_type())

        return composer


class DataAttributeFormat(enum.IntEnum):
    """Data attribute types."""
    TYPE_LENGTH_VALUE = 0x00
    TYPE_VALUE = 0x80


@attr.s
class DataAttributeTypeValue(DataAttributeBase):
    """Data attribute type/value parser."""

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    def _get_format(cls):
        return DataAttributeFormat.TYPE_VALUE


@attr.s
class DataAttributeTypeValueEnumCoded(DataAttributeTypeValue):
    """Data attribute type/value parser where the type is an enum."""

    value: typing.Any = attr.ib()

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_enum_type(cls):
        raise NotImplementedError()

    @value.validator
    def _validate_value(self, _, value):
        enum_type = self._get_enum_type()
        if not isinstance(value, enum_type):
            raise InvalidValue(value, type(self), 'value')

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_numeric_enum_coded('value', cls._get_enum_type())

        return cls(value=parser['value']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric_enum_coded(self.value)

        return composer.composed_bytes


@attr.s
class DataAttributeKeyLength(DataAttributeTypeValue):
    """Key Length transform attribute (TV format).

    The Key Length attribute has the following format:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |A|       Attribute Type        |    Key Length (in bits)       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar key_length: Key length in bits
    """

    value: int = attr.ib(validator=attr.validators.and_(
        attr.validators.instance_of(int),
        attr.validators.ge(0),
        attr.validators.lt(2**64)
    ))

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)
        parser.parse_numeric('value', 2)

        return cls(value=parser['value']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_numeric(self.value, 2)

        return composer.composed_bytes


@attr.s
class DataAttributeLength(DataAttributeBase):
    """Length transform attribute (TLV format).

    The Key Length attribute has the following format:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |A|       Attribute Type        |    Key Length (in bits)       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    :ivar key_length: Key length in bits
    """

    value: int = attr.ib(validator=attr.validators.and_(
        attr.validators.instance_of(int),
        attr.validators.ge(0),
        attr.validators.lt(2**64)
    ))

    @classmethod
    @abc.abstractmethod
    def get_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_size(cls):
        raise NotImplementedError()

    @classmethod
    def _get_format(cls):
        return DataAttributeFormat.TYPE_VALUE

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        if parser['format'] == DataAttributeFormat.TYPE_LENGTH_VALUE:
            parser.parse_numeric('size', 2)
            parser.parse_numeric('value', parser['size'])
        else:
            parser.parse_numeric('value', cls._get_size())

        return cls(value=parser['value']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        if self._get_format() == DataAttributeFormat.TYPE_LENGTH_VALUE:
            composer.compose_numeric(self._get_size(), 2)
            composer.compose_numeric(self.value, self._get_size())
        else:
            composer.compose_numeric(self.value, self._get_size())

        return composer.composed_bytes
