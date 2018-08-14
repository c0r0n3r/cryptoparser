#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import struct

import six

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue
import cryptoparser.common.utils


@six.add_metaclass(abc.ABCMeta)
class ParsableBase(object):
    @classmethod
    def parse_mutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        del parsable[:parsed_length]
        return parsed_object

    @classmethod
    def parse_immutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        unparsed_bytes = parsable[parsed_length:]
        return parsed_object, unparsed_bytes

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


class ParserBase(object):
    def __init__(self, parsable):
        self._parsable = parsable
        self._parsed_length = 0
        self._parsed_values = dict()

    def keys(self):
        return self._parsed_values.keys()

    def __getitem__(self, key):
        return self._parsed_values[key]

    @property
    def parsed_length(self):
        return self._parsed_length

    @property
    def unparsed_length(self):
        return len(self._parsable) - self._parsed_length

    def parse_parsable(self, name, parsable_class):
        parsed_object, unparsed_bytes = parsable_class.parse_immutable(
            self._parsable[self._parsed_length:]
        )
        self._parsed_length += len(self._parsable) - self._parsed_length - len(unparsed_bytes)
        self._parsed_values[name] = parsed_object


class ParserText(ParserBase):
    def __init__(self, parsable, encoding='ascii'):
        super(ParserText, self).__init__(parsable)
        self._encoding = encoding

    def _check_separators(self, name, count_offset, separator, min_count, max_count):
        count = count_offset
        while count < len(self._parsable) and self._parsable[count:].startswith(separator):
            count += len(separator)
        count -= count_offset

        if count < min_count or count > max_count:
            raise InvalidValue(self._parsable[count_offset:count_offset + count], type(self), name)

        return count

    def parse_separator(self, separator, min_length=1, max_length=1):
        separator = bytearray(separator, self._encoding)
        self._parsed_length += self._check_separators(
            'separator', self._parsed_length, separator, min_length, max_length
        )

    def _parse_numeric_array(self, name, item_num, separator, item_numeric_class):
        value = list()
        last_item_offset = self._parsed_length
        item_offset = self._parsed_length
        while True:
            while item_offset < len(self._parsable) and chr(self._parsable[item_offset]).isdigit():
                item_offset += 1

            if item_offset == last_item_offset:
                raise InvalidValue(self._parsable[self._parsed_length:], type(self), name)

            if item_offset != last_item_offset:
                value.append(item_numeric_class(self._parsable[last_item_offset:item_offset]))

            if item_offset == len(self._parsable) or (item_num is not None and len(value) == item_num):
                break

            if separator:
                try:
                    item_offset += self._check_separators(name, item_offset, separator, 1, 1)
                except InvalidValue:
                    raise InvalidValue(self._parsable[self._parsed_length:item_offset], type(self), name)

            last_item_offset = item_offset

        self._parsed_length = item_offset
        self._parsed_values[name] = value

    def parse_numeric(self, name, numeric_class=int):
        self._parse_numeric_array(name, 1, None, numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, separator, numeric_class=int):
        separator = bytearray(separator, self._encoding)
        self._parse_numeric_array(name, item_num, separator, numeric_class)

    def _parse_string_by_length(self, name, item_min_length, item_max_length, item_class):
        if item_min_length > self.unparsed_length:
            raise NotEnoughData(item_min_length - self.unparsed_length)

        if item_max_length is None:
            parsable_length = len(self._parsable) - self.parsed_length
        else:
            parsable_length = min(item_max_length, self.unparsed_length)

        value = self._parsable[self._parsed_length:self._parsed_length + parsable_length]
        try:
            self._parsed_values[name] = item_class(value.decode(self._encoding))
        except UnicodeError:
            raise InvalidValue(value, type(self), name)
        except ValueError:
            raise InvalidValue(value, type(self), name)

        self._parsed_length += parsable_length

    def parse_string_by_length(self, name, min_length=1, max_length=None, item_class=str):
        self._parse_string_by_length(name, min_length, max_length, item_class)

    def _parse_string_until_separator(self, name, item_offset, separator, item_class, may_end=False):
        item_end = self._parsable.find(separator, item_offset)
        if item_end < 0:
            if may_end:
                item_end = len(self._parsable)
            else:
                raise InvalidValue(self._parsable[item_offset:], type(self), name)

        try:
            item = item_class(self._parsable[item_offset:item_end].decode(self._encoding))
        except UnicodeError:
            raise InvalidValue(self._parsable[item_offset:], type(self), name)
        except ValueError:
            raise InvalidValue(self._parsable[item_offset:], type(self), name)

        return item, item_end - item_offset

    def parse_string_until_separator(self, name, separator, item_class=str):
        separator = bytearray(separator, self._encoding)
        parsed_value, parsed_length = self._parse_string_until_separator(
            name, self._parsed_length, separator, item_class, False
        )

        self._parsed_values[name] = parsed_value
        self._parsed_length += parsed_length

    def parse_string_until_separator_or_end(self, name, separator, item_class=str):
        separator = bytearray(separator, self._encoding)
        parsed_value, parsed_length = self._parse_string_until_separator(
            name, self._parsed_length, separator, item_class, True
        )

        self._parsed_values[name] = parsed_value
        self._parsed_length += parsed_length

    def _parse_string_array(self, name, separator, item_num=None, item_class=str):
        value = []
        item_offset = self._parsed_length
        separator = bytearray(separator, self._encoding)

        while item_offset < len(self._parsable):
            parsed_value, parsed_length = self._parse_string_until_separator(
                name, item_offset, separator, item_class, True
            )

            value.append(item_class(parsed_value))
            item_offset += parsed_length

            if item_offset == len(self._parsable) or (item_num is not None and len(value) == item_num):
                break

            item_offset += self._check_separators(name, item_offset, separator, 1, 1)

        self._parsed_values[name] = value
        self._parsed_length = item_offset

    def parse_string_array(self, name, separator, item_class=str):
        self._parse_string_array(name, separator, item_class)


class ParserBinary(ParserBase):
    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
        8: '!Q',
    }

    def _parse_numeric(self, item_offset, item_size, item_numeric_class=int):
        item_bytes = self._parsable[item_offset:item_offset + item_size]
        if item_size == 3:
            item_bytes = b'\x00' + item_bytes

        item = struct.unpack(
            self._INT_FORMATER_BY_SIZE[item_size],
            item_bytes
        )[0]
        try:
            value = item_numeric_class(item)
        except ValueError:
            raise InvalidValue(item, item_numeric_class)

        return value

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_length + (item_num * item_size) > len(self._parsable):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_length)

        if item_size not in self._INT_FORMATER_BY_SIZE:
            raise NotImplementedError()

        value = [
            self._parse_numeric(item_offset, item_size, item_numeric_class)
            for item_offset in range(self._parsed_length, self._parsed_length + (item_num * item_size), item_size)
        ]

        self._parsed_length += item_num * item_size
        self._parsed_values[name] = value

    def parse_numeric(self, name, size, numeric_class=int):
        self._parse_numeric_array(name, 1, size, numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, item_size, numeric_class=int):
        self._parse_numeric_array(name, item_num, item_size, numeric_class)

    def _parse_bytes(self, item_offset, item_size):
        if len(self._parsable) - item_offset < item_size:
            raise NotEnoughData(bytes_needed=item_size - (len(self._parsable) - item_offset))

        return self._parsable[item_offset: item_offset + item_size]

    def parse_bytes(self, name, size):
        if self.unparsed_length < size:
            raise NotEnoughData(bytes_needed=size - self.unparsed_length)

        self._parsed_values[name] = self._parsable[self._parsed_length: self._parsed_length + size]
        self._parsed_length += size

    def parse_string(self, name, items_size, encoding='utf-8'):
        item_size = self._parse_numeric(item_offset=self._parsed_length, item_size=items_size)
        value = self._parse_bytes(self._parsed_length + items_size, item_size)

        self._parsed_values[name] = str(value, encoding)
        self._parsed_length += items_size + item_size

    def _parse_parsable_derived(self, item_offset, item_classes, fallback_class=None):
        for item_class in item_classes:
            try:
                item, parsed_length = item_class._parse(self._parsable[item_offset:])
                break
            except InvalidValue:
                pass
        else:
            if fallback_class is not None:
                item, parsed_length = fallback_class._parse(self._parsable[item_offset:])
            else:
                raise ValueError(self._parsable[item_offset:])

        return item, parsed_length

    def _parse_parsable_derived_array(self, name, items_size, item_classes, fallback_class=None):
        if items_size > self.unparsed_length:
            raise NotEnoughData(bytes_needed=items_size - self.unparsed_length)

        items = []
        unparsed_bytes = self._parsable[self._parsed_length:self._parsed_length + items_size]

        while unparsed_bytes:
            for item_class in item_classes:
                try:
                    item, unparsed_bytes = item_class.parse_immutable(unparsed_bytes)
                    break
                except InvalidValue:
                    pass
            else:
                if fallback_class is not None:
                    item, unparsed_bytes = fallback_class.parse_immutable(unparsed_bytes)
                else:
                    raise ValueError(unparsed_bytes)

            items.append(item)

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def parse_parsable_array(self, name, items_size, item_class):
        if self.unparsed_length < items_size:
            raise NotEnoughData(items_size)

        try:
            return self._parse_parsable_derived_array(name, items_size, [item_class, ])
        except ValueError as e:
            raise InvalidValue(e.args[0], item_class, name)

    def parse_parsable_derived_array(self, name, items_size, item_base_class, fallback_class=None):
        item_classes = cryptoparser.common.utils.get_leaf_classes(item_base_class)
        try:
            return self._parse_parsable_derived_array(name, items_size, item_classes, fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            raise InvalidValue(e.args[0], item_base_class)

    def parse_variant(self, name, variant):
        parsed_object, value_length = variant.parse(self._parsable[self._parsed_length:])

        self._parsed_values[name] = parsed_object
        self._parsed_length += value_length


class ComposerBase(object):
    def __init__(self):
        self._composed = bytearray()

    def compose_parsable(self, value):
        self._composed += value.compose()

    def compose_parsable_array(self, values):
        composed = type(self._composed)()

        for item in values:
            composed += item.compose()

        self._composed += composed

    @property
    def composed(self):
        return bytearray(self._composed)

    @property
    def composed_length(self):
        return len(self._composed)


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

    def _compose_string_array(self, values, separator):
        separator = bytes(separator, self._encoding)
        composed_str = bytearray()

        for value in values:
            try:
                composed_str += value.encode(self._encoding)
            except UnicodeError:
                raise InvalidValue(value, type(self))

            composed_str += separator

        self._composed += composed_str[:len(composed_str) - len(separator)]

    def compose_string(self, value):
        self._compose_string_array([value, ], '')

    def compose_string_array(self, value, separator=','):
        self._compose_string_array(value, separator)

    def compose_separator(self, value):
        self.compose_string(value)


class ComposerBinary(ComposerBase):
    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
        8: '!Q',
    }

    def __init__(self):
        super(ComposerBinary, self).__init__()
        self._composed = bytearray()

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                composed_bytes += struct.pack(
                    self._INT_FORMATER_BY_SIZE[item_size],
                    value
                )

                if item_size == 3:
                    del composed_bytes[-4]

            except struct.error:
                raise InvalidValue(value, int)

        self._composed += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

    def compose_parsable(self, value):
        self._composed += value.compose()

    def compose_parsable_array(self, values):
        composed_bytes = bytearray()

        for item in values:
            composed_bytes += item.compose()

        self._composed += composed_bytes

    def compose_bytes(self, value):
        self._composed += value

    @property
    def composed_bytes(self):
        return bytearray(self._composed)

    @property
    def composed_length(self):
        return len(self._composed)
