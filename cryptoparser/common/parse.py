# -*- coding: utf-8 -*-

import abc
import datetime
import enum
import struct
import time

import attr
import six
from six.moves import collections_abc

import dateutil
import dateutil.parser
import dateutil.tz

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataEnumCodedBase

from cryptoparser.common.exception import InvalidType, NotEnoughData, TooMuchData
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


class ParserCRLF(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string('crlf', '\r\n')

        return ParserCRLF(), 2

    def compose(self):
        return b'\r\n'


_SIZE_TO_FORMAT = {
    1: 'B',
    2: 'H',
    3: 'I',
    4: 'I',
    8: 'Q',
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
            self._parsed_values = {}

    def __len__(self):
        return len(self._parsed_values)

    def __iter__(self):
        return iter(self._parsed_values)

    def __getitem__(self, key):
        return self._parsed_values[key]

    def __delitem__(self, key):
        del self._parsed_values[key]

    @property
    def parsed_length(self):
        return self._parsed_length

    @property
    def unparsed(self):
        return self._parsable[self._parsed_length:]

    @property
    def unparsed_length(self):
        return len(self._parsable) - self._parsed_length

    def parse_parsable(self, name, parsable_class, item_size=None):
        if item_size is None:
            parsed_object, parsed_length = parsable_class.parse_immutable(
                self._parsable[self._parsed_length:]
            )
        else:
            parsable_length, _ = self._parse_numeric_array(name, 1, item_size, int)
            parsable_length = parsable_length[0]
            parsed_object = parsable_class.parse_exact_size(
                self._parsable[self._parsed_length + item_size:self._parsed_length + parsable_length + item_size]
            )
            parsed_length = item_size + parsable_length

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
            value = six.ensure_text(value, encoding)
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
        separators = six.ensure_binary(separators, self._encoding)

        count = 0
        actual_offset = count_offset
        while actual_offset < len(self._parsable) and self._parsable[actual_offset:actual_offset + 1] in separators:
            actual_offset += 1
            count += 1

            if max_count is not None and count > max_count:
                raise InvalidValue(self._parsable[count_offset:], type(self), name)

        if min_count is not None and count < min_count:
            raise InvalidValue(self._parsable[count_offset:], type(self), name)

        return actual_offset - count_offset

    def parse_separator(self, separator, min_length=1, max_length=None):
        self._parsed_length += self._check_separators(
            'separator', self._parsed_length, separator, min_length, max_length
        )

    def _parse_numeric_array(  # pylint: disable=too-many-arguments
            self, name, item_num, separator, converter, is_floating):
        value = []
        floating_point_found = False
        last_item_offset = self._parsed_length
        item_offset = self._parsed_length
        while True:
            while item_offset < len(self._parsable) and self._parsable[item_offset:item_offset + 1].isdigit():
                item_offset += 1

            if item_offset == last_item_offset:
                raise InvalidValue(self._parsable[self._parsed_length:], type(self), name)

            if (is_floating and
                    not floating_point_found and item_offset < len(self._parsable) and
                    six.indexbytes(self._parsable, item_offset) == ord('.')):
                item_offset += 1
                floating_point_found = True
                continue

            value.append(converter(self._parsable[last_item_offset:item_offset]))

            if item_offset == len(self._parsable) or (item_num is not None and len(value) == item_num):
                break

            if separator:
                try:
                    item_offset += self._check_separators(name, item_offset, separator, 1, 1)
                except InvalidValue as e:
                    six.raise_from(InvalidValue(self._parsable[self._parsed_length:item_offset], type(self), name), e)

            last_item_offset = item_offset
            floating_point_found = False

        return value, item_offset - self._parsed_length

    def parse_numeric(self, name, converter=int):
        value, parsed_length = self._parse_numeric_array(name, 1, None, converter, False)
        self._parsed_values[name] = value[0]
        self._parsed_length += parsed_length

    def parse_float(self, name, converter=float):
        value, parsed_length = self._parse_numeric_array(name, 1, None, converter, True)
        self._parsed_values[name] = value[0]
        self._parsed_length += parsed_length

    def parse_numeric_array(self, name, item_num, separator, converter=int):
        value, parsed_length = self._parse_numeric_array(name, item_num, separator, converter, False)

        self._parsed_values[name] = value
        self._parsed_length += parsed_length

    def parse_bool(self, name):
        for string_value, bool_value in (('yes', True), ('no', False)):
            try:
                self.parse_string(name, string_value)
            except InvalidValue:
                pass
            else:
                self._parsed_values[name] = bool_value
                break
        else:
            raise InvalidValue(self._parsable[self._parsed_length:], type(self), name)

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
            if not isinstance(item_class, type):
                item = item_class(six.ensure_text(self._parsable[item_offset:item_end], self._encoding))
            elif issubclass(item_class, CryptoDataEnumCodedBase):
                item = item_class.from_code(six.ensure_text(self._parsable[item_offset:item_end], self._encoding))
            elif issubclass(item_class, ParsableBaseNoABC):
                item, parsed_length = item_class.parse_immutable(self._parsable[item_offset:item_end])
                item_end = item_offset + parsed_length
            elif issubclass(item_class, six.string_types):
                item = six.ensure_text(self._parsable[item_offset:item_end], self._encoding)
            else:
                item = item_class(six.ensure_text(self._parsable[item_offset:item_end], self._encoding))
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
            may_end=False,
            separator_spaces=''
    ):
        item_end = None
        byte_separators = [six.ensure_binary(separator, self._encoding) for separator in separators]

        for separator_end in range(item_offset, len(self._parsable) + 1):
            for separator in byte_separators:
                if self._parsable[item_offset:separator_end].endswith(separator):
                    item_end = separator_end - len(separator)
                    break
            if item_end is not None:
                break
        else:
            if not may_end:
                raise InvalidValue(self._parsable[item_offset:], type(item_class), name)

            item_end = len(self._parsable)

        separator_space_count = 0
        byte_separator_spaces = six.ensure_binary(separator_spaces, self._encoding)
        while (item_end > item_offset and
                self._parsable[
                    item_end - separator_space_count - 1:
                    item_end - separator_space_count
                ] in byte_separator_spaces):
            separator_space_count += 1

        item = self._apply_item_class(
            name, item_offset, item_end - separator_space_count, separators, item_class, fallback_class, may_end
        )

        return item, item_end - item_offset - separator_space_count

    def parse_string_until_separator(self, name, separators, item_class=str, fallback_class=None):
        parsed_value, parsed_length = self._parse_string_until_separator(
            name, self._parsed_length, separators, item_class, fallback_class, False
        )

        self._parsed_values[name] = parsed_value
        self._parsed_length += parsed_length

    def parse_string_until_separator_or_end(self, name, separators, item_class=str, fallback_class=None):
        parsed_value, parsed_length = self._parse_string_until_separator(
            name, self._parsed_length, separators, item_class, fallback_class, True
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
        max_separator_count = None if skip_empty else 1

        if separator_spaces:
            item_offset += self._check_separators('separator', item_offset, separator_spaces, None, None)

        while True:
            parsed_value, parsed_length = self._parse_string_until_separator(
                name, item_offset, separator, str, None, True, separator_spaces
            )
            if parsed_length:
                if isinstance(item_class, type) and issubclass(item_class, ParsableBase):
                    parsed_value = item_class.parse_exact_size(parsed_value.encode(self._encoding))
                else:
                    parsed_value = self._apply_item_class(
                        name,
                        item_offset,
                        item_offset + parsed_length,
                        separator,
                        item_class,
                        fallback_class,
                        True
                    )
                value.append(parsed_value)
                item_offset += parsed_length
            elif not skip_empty:
                raise InvalidValue(self._parsable[item_offset:], type(self), name)

            if separator_spaces:
                item_offset += self._check_separators('separator', item_offset, separator_spaces, None, None)

            if item_offset == len(self._parsable):
                break

            item_offset += self._check_separators(name, item_offset, separator, 1, max_separator_count)
            if separator_spaces:
                item_offset += self._check_separators('separator', item_offset, separator_spaces, None, None)

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

    def parse_date_time(self, name):
        try:
            value = self._parsable[self._parsed_length:]
            date_time = dateutil.parser.parse(six.ensure_text(value, self._encoding))
        except ValueError as e:
            six.raise_from(InvalidValue(value, type(self), 'value'), e)

        self._parsed_values[name] = date_time
        self._parsed_length = len(self._parsable)

    def parse_time_delta(self, name):
        value, parsed_length = self._parse_numeric_array(name, 1, None, int, False)

        try:
            time_delta = datetime.timedelta(seconds=value[0])
        except OverflowError as e:
            six.raise_from(InvalidValue(value[0], type(self), 'value'), e)

        self._parsed_values[name] = time_delta
        self._parsed_length += parsed_length


@attr.s
class ParserBinary(ParserBase):
    byte_order = attr.ib(default=ByteOrder.NETWORK, validator=attr.validators.in_(ByteOrder))

    def parse_timestamp(self, name, milliseconds=False, item_size=8):
        value, parsed_length = self._parse_numeric_array(name, 1, item_size, int)

        self._parsed_length += parsed_length
        if value[0] == (2 ** (8 * item_size) - 1):
            self._parsed_values[name] = None
        else:
            value = value[0]
            if milliseconds:
                millis = value % 1000
                value //= 1000
            value = datetime.datetime.fromtimestamp(0x00000000ffffffff & value, dateutil.tz.UTC)
            if milliseconds:
                value += datetime.timedelta(milliseconds=millis)
            self._parsed_values[name] = value

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_length + (item_num * item_size) > len(self._parsable):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_length)

        if item_size in _SIZE_TO_FORMAT:
            value = []
            for item_offset in range(self._parsed_length, self._parsed_length + (item_num * item_size), item_size):
                item_bytes = self._parsable[item_offset:item_offset + item_size]
                if item_size == 3:
                    if self.byte_order in [ByteOrder.BIG_ENDIAN, ByteOrder.NETWORK]:
                        item_bytes = b'\x00' + item_bytes
                    else:
                        item_bytes = item_bytes + b'\x00'

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

    def parse_numeric(self, name, size, converter=int):
        value, parsed_length = self._parse_numeric_array(name, 1, size, converter)

        self._parsed_length += parsed_length
        self._parsed_values[name] = value[0]

    def parse_numeric_array(self, name, item_num, item_size, converter=int):
        value, parsed_length = self._parse_numeric_array(name, item_num, item_size, converter)

        self._parsed_length += parsed_length
        self._parsed_values[name] = value

    def parse_numeric_flags(self, name, size, flags_class, shift_left=0):
        value, parsed_length = self._parse_numeric_array(name, 1, size, int)
        value = {
            flags_class(flag & (value[0] << shift_left))
            for flag in flags_class
            if flag & (value[0] << shift_left)
        }

        self._parsed_length += parsed_length
        self._parsed_values[name] = value

    def _parse_mpint(self, mpint_length, mpint_offset, negative):
        if mpint_length % 4:
            pad_byte = six.int2byte(0xff) if negative else six.int2byte(0x00)
            pad_bytes = (4 - (mpint_length % 4)) * pad_byte
        else:
            pad_bytes = b''

        parsable = pad_bytes + self._parsable[self._parsed_length + mpint_offset:]
        parser = ParserBinary(parsable)
        parser.parse_numeric_array('mpint_part_array', (mpint_length + len(pad_bytes)) // 4, 4, int)

        value = 0
        for mpint_part in parser['mpint_part_array']:
            value = (value << 32) + mpint_part
        if negative:
            complement = 1 << (8 * (mpint_length + len(pad_bytes)))
            value -= complement

        return value

    def parse_mpint(self, name, mpint_length):
        value = self._parse_mpint(mpint_length, 0, False)

        self._parsed_values[name] = value
        self._parsed_length += mpint_length

    def parse_ssh_mpint(self, name):
        if self.unparsed_length < 4:
            raise NotEnoughData(bytes_needed=4 - self.unparsed_length)

        mpint_length, parsed_length = self._parse_numeric_array(name, 1, 4, int)
        mpint_length = mpint_length[0]

        negative = (mpint_length and (six.indexbytes(self._parsable, self._parsed_length + 4) >= 0x80))

        value = self._parse_mpint(mpint_length, 4, negative)

        self._parsed_values[name] = value
        self._parsed_length += parsed_length + mpint_length

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

    def parse_raw(self, name, size, converter=bytearray):
        parsed_bytes = self._parse_bytes(size)

        try:
            self._parsed_values[name] = converter(parsed_bytes)
        except ValueError as e:
            six.raise_from(InvalidValue(parsed_bytes, converter, name), e)

        self._parsed_length += size

    def parse_string(self, name, item_size, encoding, converter=str):
        value, parsed_length = self._parse_numeric_array(name, 1, item_size, int)
        value = value[0]
        self._parsed_length += parsed_length

        try:
            value, parsed_length = self._parse_string_by_length(name, value, value, encoding, converter)
            self._parsed_length += parsed_length
            self._parsed_values[name] = value
        except InvalidValue as e:
            raise e

    def parse_string_null_terminated(self, name, encoding, converter=str):
        try:
            length = next(iter([
                i
                for i, value in enumerate(six.iterbytes(self._parsable[self._parsed_length:]))
                if value == 0
            ]))
        except StopIteration as e:
            six.raise_from(InvalidValue(self._parsable[self._parsed_length:], str, name), e)

        value, parsed_length = self._parse_string_by_length(name, length, length, encoding, converter)
        self._parsed_length += parsed_length + 1
        self._parsed_values[name] = value

    def _parse_parsable_derived_array(self, items_size, item_classes, fallback_class=None):
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

        return items, items_size

    def parse_parsable_array(self, name, items_size, item_class, fallback_class=None):
        try:
            items, items_size = self._parse_parsable_derived_array(items_size, [item_class, ], fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_class, name), e)

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def parse_parsable_derived_array(self, name, items_size, item_base_class, fallback_class=None):
        item_classes = cryptoparser.common.utils.get_leaf_classes(item_base_class)
        try:
            items, items_size = self._parse_parsable_derived_array(items_size, item_classes, fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_base_class, name), e)

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def _remove_trailing_separator(self, items, name):
        if not isinstance(items[-1], ParserCRLF):
            raise InvalidValue(self.unparsed, type(self), name)
        del items[-1]

    def parse_parsable_list(self, name, item_class, fallback_class=None, separator_class=ParserCRLF):
        try:
            items, items_size = self._parse_parsable_derived_array(
                self.unparsed_length, [separator_class, item_class], fallback_class
            )
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_class, name), e)

        if not items:
            raise NotEnoughData(2)
        self._remove_trailing_separator(items, name)

        real_items = []
        while items:
            if len(items) % 2 == 0:
                self._remove_trailing_separator(items, name)
            else:
                if isinstance(items[-1], separator_class):
                    raise InvalidValue(self.unparsed, type(self), name)

                real_items.insert(0, items[-1])
                del items[-1]

        self._parsed_values[name] = real_items
        self._parsed_length += items_size

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
        separator = bytearray(six.ensure_binary(separator, encoding))
        composed_str = bytearray()

        for value in values:
            try:
                if isinstance(value, ParsableBaseNoABC):
                    composed_str += value.compose()
                else:
                    composed_str += six.ensure_binary(six.text_type(value), encoding)
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

        self._composed += six.ensure_binary(composed_str[:len(composed_str) - len(separator)], self._encoding)

    def compose_numeric(self, value):
        self._compose_numeric_array([value, ], separator='')

    def compose_numeric_array(self, values, separator):
        self._compose_numeric_array(values, separator)

    def compose_bool(self, value):
        self.compose_string('yes' if value else 'no')

    def compose_string(self, value):
        self._compose_string_array([value, ], encoding=self._encoding, separator='')

    def compose_string_array(self, value, separator=','):
        self._compose_string_array(value, encoding=self._encoding, separator=separator)

    @staticmethod
    def _compose_parsable(value):
        return value.compose()

    def compose_parsable(self, value):
        self._composed += self._compose_parsable(value)

    def compose_parsable_array(self, values, separator=',', fallback_class=None):
        separator = six.ensure_binary(separator, self._encoding)

        composed_items = []
        for item in values:
            if isinstance(item, (ComposerBase, ParsableBase, ParsableBaseNoABC)):
                composed_item = self._compose_parsable(item)
            elif isinstance(item, CryptoDataEnumBase):
                composed_item = six.ensure_binary(item.value.code, self._encoding)
            elif fallback_class is not None and isinstance(item, fallback_class):
                composed_item = six.ensure_binary(item, self._encoding)
            else:
                raise InvalidType()

            composed_items.append(composed_item)

        self._composed += bytearray(separator).join(composed_items)

    def compose_separator(self, value):
        self.compose_string(value)

    def compose_date_time(self, value, fmt):
        self.compose_string(value.strftime(fmt))

    def compose_time_delta(self, value):
        self.compose_numeric(int(value.total_seconds()))


@attr.s
class ComposerBinary(ComposerBase):
    byte_order = attr.ib(default=ByteOrder.NETWORK, validator=attr.validators.in_(ByteOrder))

    def compose_timestamp(self, value, milliseconds=False, item_size=8):
        if value is None:
            timestamp = 0xffffffffffffffff
        else:
            timestamp = int(time.mktime(value.timetuple())) - time.timezone

            if milliseconds:
                timestamp *= 1000
                timestamp += value.microsecond // 1000

        return self._compose_numeric_array([timestamp, ], item_size)

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                packed_bytes = struct.pack(
                    self.byte_order.value + _SIZE_TO_FORMAT[item_size],
                    value
                )

                if item_size == 3:
                    if self.byte_order in [ByteOrder.BIG_ENDIAN, ByteOrder.NETWORK]:
                        composed_bytes += packed_bytes[1:]
                    else:
                        composed_bytes += packed_bytes[:3]
                else:
                    composed_bytes += packed_bytes
            except struct.error as e:
                six.raise_from(InvalidValue(value, int), e)

        self._composed += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_enum_coded(self, value):
        self.compose_numeric_array_enum_coded([value, ])

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

    def compose_numeric_array_enum_coded(self, values):
        if not values:
            return

        self._compose_numeric_array(map(lambda value: value.value.code, values), values[0].value.get_code_size())

    def compose_numeric_flags(self, values, item_size, shift_right=0):
        flag = 0
        for value in values:
            flag |= value >> shift_right
        self._compose_numeric_array([flag, ], item_size)

    @staticmethod
    def _compose_mpint(value, length, byte_order):
        negative = value < 0

        if negative:
            positive_value = (1 << ((value.bit_length() // 8 * 8) + 8)) + value
        else:
            positive_value = value

        value_numeric_array = []
        for mpint_offset in range(0, length * 32, 32):
            value_numeric_array.append(positive_value >> mpint_offset & 0xffffffff)

        composer = ComposerBinary(byte_order=byte_order)
        composer.compose_numeric_array(reversed(value_numeric_array), 4)

        mpint_bytes = composer.composed_bytes.lstrip(b'\x00')
        if byte_order in [ByteOrder.LITTLE_ENDIAN, ByteOrder.NATIVE]:
            mpint_bytes = mpint_bytes.rstrip(b'\x00')

        return mpint_bytes

    def compose_mpint(self, value, length):
        mpint_bytes = self._compose_mpint(value, length, self.byte_order)
        if length < len(mpint_bytes):
            raise InvalidValue(length, type(self), 'mpint_length')

        pad_byte = b'\xff' if value < 0 else b'\x00'
        if self.byte_order in [ByteOrder.BIG_ENDIAN, ByteOrder.NETWORK]:
            self.compose_raw((length - len(mpint_bytes)) * pad_byte)
            self.compose_raw(mpint_bytes)
        else:
            self.compose_raw(mpint_bytes)
            self.compose_raw((length - len(mpint_bytes)) * pad_byte)

    def compose_ssh_mpint(self, value):
        negative = value < 0
        length = value.bit_length() // 32
        if value.bit_length() % 32:
            length += 1

        mpint_bytes = self._compose_mpint(value, length, self.byte_order)

        if mpint_bytes and bool(mpint_bytes[0] & 0x80) != negative:
            pad_byte = b'\xff' if negative else b'\x00'
        else:
            pad_byte = b''

        self.compose_numeric(len(pad_byte) + len(mpint_bytes), 4)
        self.compose_raw(pad_byte)
        self.compose_raw(mpint_bytes)

    def compose_parsable(self, value, item_size=None):
        composed = value.compose()
        if item_size is not None:
            self.compose_numeric(len(composed), item_size)
        self._composed += composed

    def compose_parsable_array(self, values, separator=bytearray()):
        self._composed += separator.join(map(lambda item: item.compose(), values))

    def compose_bytes(self, value, item_size, converter=bytearray):
        value_bytes = converter(value)
        self._compose_numeric_array([len(value_bytes), ], item_size)
        self.compose_raw(value_bytes)

    def compose_raw(self, value):
        self._composed += value

    def compose_string(self, value, encoding, item_size):
        try:
            value = six.ensure_binary(value, encoding)
        except UnicodeError as e:
            six.raise_from(InvalidValue(value, type(self)), e)

        self.compose_bytes(value, item_size)

    def compose_string_null_terminated(self, value, encoding):
        try:
            value = value.encode(encoding)
        except UnicodeError as e:
            six.raise_from(InvalidValue(value, type(self)), e)

        self.compose_raw(value)
        self.compose_raw(b'\x00')

    def compose_string_enum_coded(self, value, item_size):
        self.compose_string(value.value.code, 'ascii', item_size)

    @property
    def composed_bytes(self):
        return bytearray(self._composed)

    @property
    def composed_length(self):
        return len(self._composed)
