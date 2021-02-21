# -*- coding: utf-8 -*-

import abc
import enum
import struct

import attr
import six
from six.moves import collections_abc

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue
import cryptoparser.common.utils


class ParsableBaseNoABC(object):
    @classmethod
    def parse_mutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        del parsable[:parsed_length]
        return parsed_object

    @classmethod
    def parse_immutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        return parsed_object, parsed_length

    @classmethod
    def parse_exact_size(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        if len(parsable) > parsed_length:
            raise TooMuchData(parsed_length)

        return parsed_object

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@six.add_metaclass(abc.ABCMeta)
class ParsableBase(ParsableBaseNoABC):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


_SIZE_TO_FORMAT = {
    1: 'B',
    2: 'H',
    3: 'I',
    4: 'I',
}


class ByteOrder(enum.Enum):
    NATIVE = '='
    LITTLE_ENDIAN = '<'
    BIG_ENDIAN = '>'
    NETWORK = '!'


@attr.s
class ParserBase(collections_abc.Mapping):
    _parsable = attr.ib(converter=bytes, validator=attr.validators.instance_of((bytes, bytearray)))
    _parsed_length = attr.ib(init=False, default=0)
    _parsed_values = attr.ib(init=False, default=None)

    def __attrs_post_init__(self):
        if self._parsed_values is None:
            self._parsed_values = dict()

    def __len__(self):
        return len(self._parsed_values)

    def __iter__(self):
        return iter(self._parsed_values)

    def __getitem__(self, key):
        return self._parsed_values[key]

    @property
    def parsed_length(self):
        return self._parsed_length

    @property
    def unparsed(self):
        return self._parsable[self._parsed_length:]

    @property
    def unparsed_length(self):
        return len(self._parsable) - self._parsed_length

    def parse_parsable(self, name, parsable_class):
        parsed_object, parsed_length = parsable_class.parse_immutable(
            self._parsable[self._parsed_length:]
        )
        self._parsed_length += parsed_length
        self._parsed_values[name] = parsed_object

    def _parse_string_by_length(
            self,
            name,
            item_min_length,
            item_max_length,
            encoding,
            converter
    ):  # pylint: disable=too-many-arguments
        if item_min_length > self.unparsed_length:
            raise NotEnoughData(item_min_length - self.unparsed_length)

        if item_max_length is None:
            parsable_length = len(self._parsable) - self.parsed_length
        else:
            parsable_length = min(item_max_length, self.unparsed_length)

        value = self._parsable[self._parsed_length:self._parsed_length + parsable_length]
        try:
            value = value.decode(encoding)
            if converter != str:
                value = converter(value)
            self._parsed_values[name] = value
        except UnicodeError as e:
            six.raise_from(InvalidValue(value, converter, name), e)
        except ValueError as e:
            six.raise_from(InvalidValue(value, converter, name), e)

        return value, parsable_length


class ParserText(ParserBase):
    def __init__(self, parsable, encoding='ascii'):
        super(ParserText, self).__init__(parsable)
        self._encoding = encoding

    def _check_separators(  # pylint: disable=too-many-arguments
            self,
            name,
            count_offset,
            separators,
            min_count,
            max_count
    ):
        count = 0
        actual_offset = count_offset
        while actual_offset < len(self._parsable) and self._parsable[actual_offset:actual_offset + 1] in separators:
            actual_offset += 1
            count += 1

            if max_count is not None and count > max_count:
                raise InvalidValue(self._parsable[count_offset:], type(self), name)

        if count < min_count:
            raise InvalidValue(self._parsable[count_offset:], type(self), name)

        return actual_offset - count_offset

    def parse_separator(self, separator, min_length=1, max_length=1):
        separator = bytearray(separator, self._encoding)
        self._parsed_length += self._check_separators(
            'separator', self._parsed_length, separator, min_length, max_length
        )

    def _parse_numeric_array(self, name, item_num, separator, converter):
        value = list()
        last_item_offset = self._parsed_length
        item_offset = self._parsed_length
        while True:
            while item_offset < len(self._parsable) and self._parsable[item_offset:item_offset + 1].isdigit():
                item_offset += 1

            if item_offset == last_item_offset:
                raise InvalidValue(self._parsable[self._parsed_length:], type(self), name)

            if item_offset != last_item_offset:
                value.append(converter(self._parsable[last_item_offset:item_offset]))

            if item_offset == len(self._parsable) or (item_num is not None and len(value) == item_num):
                break

            if separator:
                try:
                    item_offset += self._check_separators(name, item_offset, separator, 1, 1)
                except InvalidValue as e:
                    six.raise_from(InvalidValue(self._parsable[self._parsed_length:item_offset], type(self), name), e)

            last_item_offset = item_offset

        self._parsed_length = item_offset
        self._parsed_values[name] = value

    def parse_numeric(self, name, converter=int):
        self._parse_numeric_array(name, 1, None, converter)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, separator, converter=int):
        separator = bytearray(separator, self._encoding)
        self._parse_numeric_array(name, item_num, separator, converter)

    def parse_string(self, name, value):
        min_length = len(value)
        max_length = min_length
        try:
            actual_value, parsed_length = self._parse_string_by_length(
                name, min_length, max_length, self._encoding, str
            )
        except NotEnoughData as e:
            six.raise_from(
                InvalidValue(self._parsable[self._parsed_length:min_length - e.bytes_needed], type(self), name), e
            )

        if value != actual_value:
            raise InvalidValue(self._parsable[self._parsed_length:self._parsed_length + max_length], type(self), name)

        self._parsed_values[name] = value
        self._parsed_length += parsed_length

    def parse_string_by_length(self, name, min_length=1, max_length=None, item_class=str):
        value, parsed_length = self._parse_string_by_length(name, min_length, max_length, self._encoding, item_class)
        self._parsed_values[name] = value
        self._parsed_length += parsed_length

    def _apply_item_class(  # pylint: disable=too-many-arguments
            self,
            name,
            item_offset,
            item_end,
            separator,
            item_class,
            fallback_class,
            may_end):
        try:
            if issubclass(item_class, ParsableBaseNoABC):
                item = item_class.parse_exact_size(self._parsable[item_offset:item_end])
            elif issubclass(item_class, str):
                item = self._parsable[item_offset:item_end].decode(self._encoding)
            else:
                item = item_class(self._parsable[item_offset:item_end].decode(self._encoding))
        except (InvalidValue, ValueError, UnicodeError) as e:
            if fallback_class is not None:
                parsed_value, parsed_length = self._parse_string_until_separator(
                    name, item_offset, separator, fallback_class, None, may_end
                )
                item_offset += parsed_length
                return parsed_value

            six.raise_from(InvalidValue(self._parsable[item_offset:], type(self), name), e)

        return item

    def _parse_string_until_separator(  # pylint: disable=too-many-arguments
            self,
            name,
            item_offset,
            separators,
            item_class,
            fallback_class,
            may_end=False
    ):
        for item_end in range(item_offset, len(self._parsable)):
            if self._parsable[item_end] in separators:
                break
        else:
            if not may_end:
                raise InvalidValue(self._parsable[item_offset:], type(self), name)

            item_end = len(self._parsable)

        item = self._apply_item_class(name, item_offset, item_end, separators, item_class, fallback_class, may_end)

        return item, item_end - item_offset

    def parse_string_until_separator(self, name, separator, item_class=str, fallback_class=None):
        separator = bytearray(separator, self._encoding)
        parsed_value, parsed_length = self._parse_string_until_separator(
            name, self._parsed_length, separator, item_class, fallback_class, False
        )

        self._parsed_values[name] = parsed_value
        self._parsed_length += parsed_length

    def parse_string_until_separator_or_end(self, name, separator, item_class=str, fallback_class=None):
        separator = bytearray(separator, self._encoding)
        parsed_value, parsed_length = self._parse_string_until_separator(
            name, self._parsed_length, separator, item_class, fallback_class, True
        )

        self._parsed_values[name] = parsed_value
        self._parsed_length += parsed_length

    def _parse_string_array(
            self,
            name,
            separator,
            max_item_num=None,
            item_class=str,
            fallback_class=None,
            separator_spaces='',
            skip_empty=False
    ):  # pylint: disable=too-many-arguments
        value = []
        item_offset = self._parsed_length
        separator = separator.encode(self._encoding)
        separator_spaces = separator_spaces.encode(self._encoding)
        max_separator_count = None if skip_empty else 1

        if separator_spaces:
            item_offset += self._check_separators('separator', item_offset, separator_spaces, 0, None)

        while True:
            parsed_value, parsed_length = self._parse_string_until_separator(
                name, item_offset, separator + separator_spaces, str, None, True
            )
            if parsed_length:
                parsed_value = self._apply_item_class(
                    name,
                    item_offset,
                    item_offset + parsed_length,
                    separator + separator_spaces,
                    item_class,
                    fallback_class,
                    True
                )
                value.append(parsed_value)
                item_offset += parsed_length
            elif not skip_empty:
                raise InvalidValue(self._parsable[item_offset:], type(self), name)

            if item_offset == len(self._parsable):
                break

            if separator_spaces:
                item_offset += self._check_separators('separator', item_offset, separator_spaces, 0, None)
            item_offset += self._check_separators(name, item_offset, separator, 1, max_separator_count)
            if separator_spaces:
                item_offset += self._check_separators('separator', item_offset, separator_spaces, 0, None)

            if item_offset == len(self._parsable):
                break
            if max_item_num is not None and len(value) == max_item_num:
                break

        self._parsed_values[name] = value
        self._parsed_length = item_offset

    def parse_string_array(
            self,
            name,
            separator,
            item_class=str,
            fallback_class=None,
            separator_spaces='',
            skip_empty=False,
            max_item_num=None,
    ):  # pylint: disable=too-many-arguments
        self._parse_string_array(
            name,
            separator,
            max_item_num=max_item_num,
            item_class=item_class,
            fallback_class=fallback_class,
            separator_spaces=separator_spaces,
            skip_empty=skip_empty
        )


@attr.s
class ParserBinary(ParserBase):
    byte_order = attr.ib(default=ByteOrder.NETWORK, validator=attr.validators.in_(ByteOrder))

    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
        8: '!Q',
    }

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_length + (item_num * item_size) > len(self._parsable):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_length)

        if item_size in _SIZE_TO_FORMAT:
            value = list()
            for item_offset in range(self._parsed_length, self._parsed_length + (item_num * item_size), item_size):
                item_bytes = self._parsable[item_offset:item_offset + item_size]
                if item_size == 3:
                    item_bytes = b'\x00' + item_bytes

                item = struct.unpack(
                    self.byte_order.value + _SIZE_TO_FORMAT[item_size],
                    item_bytes
                )[0]
                try:
                    value.append(item_numeric_class(item))
                except ValueError as e:
                    six.raise_from(InvalidValue(item, item_numeric_class, name), e)
        else:
            raise NotImplementedError()

        return value, item_num * item_size

    def parse_numeric(self, name, size, numeric_class=int):
        value, parsed_length = self._parse_numeric_array(name, 1, size, numeric_class)

        self._parsed_length += parsed_length
        self._parsed_values[name] = value[0]

    def parse_numeric_array(self, name, item_num, item_size, numeric_class=int):
        value, parsed_length = self._parse_numeric_array(name, item_num, item_size, numeric_class)

        self._parsed_length += parsed_length
        self._parsed_values[name] = value

    def parse_numeric_flags(self, name, size, flags_class):
        value, parsed_length = self._parse_numeric_array(name, 1, size, int)
        value = [
            flags_class(flag & value[0])
            for flag in flags_class
            if flag & value[0]
        ]

        self._parsed_length += parsed_length
        self._parsed_values[name] = value

    def _parse_bytes(self, size):
        if self.unparsed_length < size:
            raise NotEnoughData(bytes_needed=size - self.unparsed_length)

        return self._parsable[self._parsed_length: self._parsed_length + size]

    def parse_bytes(self, name, size, converter=bytearray):
        value, parsed_length = self._parse_numeric_array(name, 1, size, int)
        value = value[0]

        self._parsed_length += parsed_length
        try:
            parsed_bytes = self._parse_bytes(value)
        except NotEnoughData:
            self._parsed_length -= parsed_length
            raise

        try:
            self._parsed_values[name] = converter(parsed_bytes)
        except ValueError as e:
            six.raise_from(InvalidValue(value, converter, name), e)
        self._parsed_length += len(parsed_bytes)

    def parse_raw(self, name, size):
        parsed_bytes = self._parse_bytes(size)

        self._parsed_values[name] = parsed_bytes
        self._parsed_length += size

    def parse_string(self, name, item_size, encoding):
        value, parsed_length = self._parse_numeric_array(name, 1, item_size, int)
        value = value[0]
        self._parsed_length += parsed_length

        try:
            value, parsed_length = self._parse_string_by_length(name, value, value, encoding, str)
            self._parsed_length += parsed_length
            self._parsed_values[name] = value
        except InvalidValue as e:
            raise e

    def _parse_parsable_derived_array(self, name, items_size, item_classes, fallback_class=None):
        if items_size > self.unparsed_length:
            raise NotEnoughData(bytes_needed=items_size - self.unparsed_length)

        items = []
        unparsed_bytes = self._parsable[self._parsed_length:self._parsed_length + items_size]

        while unparsed_bytes:
            for item_class in item_classes:
                try:
                    item, parsed_length = item_class.parse_immutable(unparsed_bytes)
                    break
                except InvalidValue:
                    pass
            else:
                if fallback_class is not None:
                    item, parsed_length = fallback_class.parse_immutable(unparsed_bytes)
                else:
                    raise ValueError(unparsed_bytes)

            unparsed_bytes = unparsed_bytes[parsed_length:]
            items.append(item)

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def parse_parsable_array(self, name, items_size, item_class, fallback_class=None):
        try:
            self._parse_parsable_derived_array(name, items_size, [item_class, ], fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_class, name), e)

    def parse_parsable_derived_array(self, name, items_size, item_base_class, fallback_class=None):
        item_classes = cryptoparser.common.utils.get_leaf_classes(item_base_class)
        try:
            self._parse_parsable_derived_array(name, items_size, item_classes, fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_base_class, name), e)

    def parse_variant(self, name, variant):
        parsed_object, value_length = variant.parse(self._parsable[self._parsed_length:])

        self._parsed_values[name] = parsed_object
        self._parsed_length += value_length


@attr.s
class ComposerBase(object):
    _composed = attr.ib(init=False, default=bytes())

    @property
    def composed(self):
        return self._composed

    @property
    def composed_length(self):
        return len(self._composed)

    def _compose_string_array(self, values, encoding, separator):
        separator = bytearray(separator.encode(encoding))
        composed_str = bytearray()

        for value in values:
            try:
                if isinstance(value, ParsableBaseNoABC):
                    composed_str += value.compose()
                else:
                    composed_str += value.encode(encoding)
            except UnicodeError as e:
                six.raise_from(InvalidValue(value, type(self)), e)

            composed_str += separator

        self._composed += composed_str[:len(composed_str) - len(separator)]


class ComposerText(ComposerBase):
    def __init__(self, encoding='ascii'):
        super(ComposerText, self).__init__()
        self._encoding = encoding

    def _compose_numeric_array(self, values, separator):
        composed_str = str()

        for value in values:
            composed_str += '{:d}{}'.format(value, separator)

        self._composed += composed_str[:len(composed_str) - len(separator)].encode(self._encoding)

    def compose_numeric(self, value):
        self._compose_numeric_array([value, ], separator='')

    def compose_numeric_array(self, values, separator):
        self._compose_numeric_array(values, separator)

    def compose_string(self, value):
        self._compose_string_array([value, ], encoding=self._encoding, separator='')

    def compose_string_array(self, value, separator=','):
        self._compose_string_array(value, encoding=self._encoding, separator=separator)

    def compose_parsable(self, value):
        self._composed += value.compose()

    def compose_parsable_array(self, values, separator=','):
        separator = separator.encode(self._encoding)

        self._composed += bytearray(separator).join(map(lambda item: item.compose(), values))

    def compose_separator(self, value):
        self.compose_string(value)


@attr.s
class ComposerBinary(ComposerBase):
    byte_order = attr.ib(default=ByteOrder.NETWORK, validator=attr.validators.in_(ByteOrder))

    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                composed_bytes += struct.pack(
                    self.byte_order.value + _SIZE_TO_FORMAT[item_size],
                    value
                )

                if item_size == 3:
                    del composed_bytes[-4]

            except struct.error as e:
                six.raise_from(InvalidValue(value, int), e)

        self._composed += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

    def compose_numeric_flags(self, values, item_size):
        flag = 0
        for value in values:
            flag |= value
        self._compose_numeric_array([flag, ], item_size)

    def compose_parsable(self, value, item_size=None):
        composed = value.compose()
        if item_size is not None:
            self.compose_numeric(len(composed), item_size)
        self._composed += composed

    def compose_parsable_array(self, values):
        self._composed += bytearray().join(map(lambda item: item.compose(), values))

    def compose_bytes(self, value, item_size, converter=bytearray):
        value_bytes = converter(value)
        self._compose_numeric_array([len(value_bytes), ], item_size)
        self.compose_raw(value_bytes)

    def compose_raw(self, value):
        self._composed += value

    def compose_string(self, value, encoding, item_size):
        try:
            value = value.encode(encoding)
        except UnicodeError as e:
            six.raise_from(InvalidValue(value, type(self)), e)

        self.compose_bytes(value, item_size)

    @property
    def composed_bytes(self):
        return bytearray(self._composed)

    @property
    def composed_length(self):
        return len(self._composed)
